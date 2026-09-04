// HA-WBC-2 开机卡控制台:集中管理局域网内的物联网开机卡。
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"ha-wbc-console/internal/homekit"
	"ha-wbc-console/internal/mockdev"
	"ha-wbc-console/internal/server"
	"ha-wbc-console/internal/store"
)

//go:embed all:web
var webFiles embed.FS

// version 由构建脚本通过 -ldflags 注入。
var version = "dev"

func main() {
	addr := flag.String("addr", ":8088", "监听地址,如 :8088 或 127.0.0.1:8088")
	dataPath := flag.String("data", "ha-wbc-data.json", "数据文件路径")
	logPath := flag.String("log", "", "日志文件路径(默认输出到终端;文件自动轮转,总占用不超过约 2MB)")
	tlsOn := flag.Bool("tls", false, "启用 HTTPS(未提供证书时自动生成自签名证书;放在 HTTPS 反向代理后面时无需开启)")
	certFile := flag.String("cert", "", "TLS 证书文件路径(需与 -key 同时提供)")
	keyFile := flag.String("key", "", "TLS 私钥文件路径")
	mockN := flag.Int("mock", 0, "启动 N 台模拟开机卡用于演示(0 表示关闭)")
	showVersion := flag.Bool("version", false, "显示版本号")
	flag.Parse()

	if *showVersion {
		fmt.Println("ha-wbc-console", version)
		return
	}

	log.SetFlags(log.Ldate | log.Ltime)
	if *logPath != "" {
		lw, err := newRotatingWriter(*logPath)
		if err != nil {
			log.Fatalf("打开日志文件失败: %v", err)
		}
		log.SetOutput(lw)
	}
	log.Printf("HA-WBC-2 开机卡控制台 %s", version)

	if *mockN > 0 {
		addrs, err := mockdev.Start(*mockN, 18080)
		if err != nil {
			log.Fatalf("启动模拟设备失败: %v", err)
		}
		log.Printf("[mock] 共启动 %d 台模拟设备,添加设备时地址填 %v,WiFi 密码 %s", len(addrs), addrs, mockdev.Password)
	}

	st, err := store.Open(*dataPath)
	if err != nil {
		log.Fatalf("打开数据文件失败: %v", err)
	}
	if !st.Initialized() {
		log.Printf("首次运行:请在网页上设置管理员密码")
	}

	webFS, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatalf("加载内嵌前端资源失败: %v", err)
	}

	homeKitManager, err := homekit.New(st, version)
	if err != nil {
		log.Fatalf("初始化 HomeKit 失败: %v", err)
	}
	if err := homeKitManager.Start(); err != nil {
		// 控制台仍可启动，管理员可在系统设置中修正端口或重新启用。
		log.Printf("[homekit] 自动启动失败: %v", err)
	}

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           server.New(st, webFS, homeKitManager),
		ReadHeaderTimeout: 10 * time.Second,
	}

	useTLS := *tlsOn || (*certFile != "" && *keyFile != "")
	if useTLS && (*certFile == "" || *keyFile == "") {
		c, k, err := ensureSelfSignedCert(filepath.Dir(*dataPath))
		if err != nil {
			log.Fatalf("准备 TLS 证书失败: %v", err)
		}
		*certFile, *keyFile = c, k
	}

	go func() {
		var err error
		if useTLS {
			log.Printf("控制台已启动: https://%s", displayAddr(*addr))
			err = httpServer.ListenAndServeTLS(*certFile, *keyFile)
		} else {
			log.Printf("控制台已启动: http://%s", displayAddr(*addr))
			err = httpServer.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("服务启动失败: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Printf("正在退出...")
	homeKitManager.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}

// displayAddr 将 ":8088" 之类的监听地址转成可点击的 URL 主机部分。
func displayAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "127.0.0.1:" + port
	}
	return net.JoinHostPort(host, port)
}

// maxLogSize 单个日志文件上限;超过后轮转为 .old(仅保留一份),
// 连同当前文件总占用不超过约 2 倍该值,适合存储空间有限的路由器等设备。
const maxLogSize = 1 << 20 // 1MB

// rotatingWriter 带大小上限与单份备份轮转的日志写入器。
type rotatingWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func newRotatingWriter(path string) (*rotatingWriter, error) {
	w := &rotatingWriter{path: path}
	if err := w.openFile(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotatingWriter) openFile() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f = f
	w.size = st.Size()
	return nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+int64(len(p)) > maxLogSize {
		w.f.Close()
		_ = os.Rename(w.path, w.path+".old") // 覆盖旧备份
		if err := w.openFile(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}
