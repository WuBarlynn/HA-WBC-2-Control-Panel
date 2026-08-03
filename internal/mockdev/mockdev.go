// Package mockdev 提供一个模拟的 HA-WBC-2 开机卡 HTTP 服务,
// 用于在没有真实硬件时演示与验证控制台功能。
package mockdev

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Password 模拟设备的 WiFi 密码。
const Password = "12345678"

type device struct {
	mu        sync.Mutex
	addr      string
	sn        string
	token     string
	power     bool
	autoStart bool
	childLock bool
	ssid      string
	fw        string
	progress  int
	updating  bool
}

// Start 启动 n 台模拟设备,返回它们的监听地址。
func Start(n, basePort int) ([]string, error) {
	addrs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		port := basePort + i
		d := &device{
			sn:    fmt.Sprintf("MOCK%06d", port),
			power: i%2 == 0,
			ssid:  "Sumsg WiFi",
			fw:    "1.0.1",
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return nil, fmt.Errorf("模拟设备端口 %d 监听失败: %w", port, err)
		}
		d.addr = ln.Addr().String()
		srv := &http.Server{Handler: d.mux()}
		go func() { _ = srv.Serve(ln) }()
		addrs = append(addrs, d.addr)
		log.Printf("[mock] 模拟开机卡已启动: %s (WiFi 密码: %s)", d.addr, Password)
	}
	return addrs, nil
}

func (d *device) mux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/api/login", d.handleLogin)
	m.HandleFunc("/api/getConnectStatus", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		writeJSON(w, map[string]any{"status": "ok", "pE": false, "oL": true, "wP": true, "fV": d.fw, "wI": d.addr})
	})
	m.HandleFunc("/api/getUpdateProgress", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		writeJSON(w, map[string]any{"status": "ok", "progress": fmt.Sprintf("%d", d.progress)})
	})
	// 需要认证的接口
	m.HandleFunc("/api/getDeviceInfo", d.auth(d.handleInfo))
	m.HandleFunc("/api/getDeviceState", d.auth(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		writeJSON(w, map[string]any{
			"status": "ok",
			"tP":     29,
			"pW":     d.power,
			"aS":     d.autoStart,
			"cL":     d.childLock,
		})
	}))
	m.HandleFunc("/api/verifyToken", d.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	m.HandleFunc("/api/setWiFi", d.auth(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		d.mu.Lock()
		d.ssid = r.FormValue("ssid")
		d.mu.Unlock()
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	m.HandleFunc("/api/getWifiList", d.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "ok", "list": []map[string]any{
			{"s": "Sumsg WiFi", "r": -45},
			{"s": "TP-LINK_5G_A1", "r": -58},
			{"s": "ChinaNet-2.4G", "r": -70},
			{"s": "Xiaomi_88", "r": -79},
			{"s": "CMCC-Guest", "r": -86},
		}})
	}))
	m.HandleFunc("/api/restart", d.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	m.HandleFunc("/api/setPowerState", d.auth(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		d.mu.Lock()
		d.power = r.FormValue("state") == "true"
		d.mu.Unlock()
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	m.HandleFunc("/api/setAutoStartState", d.auth(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		d.mu.Lock()
		d.autoStart = r.FormValue("state") == "true"
		d.mu.Unlock()
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	m.HandleFunc("/api/setChildLockState", d.auth(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		d.mu.Lock()
		d.childLock = r.FormValue("state") == "true"
		d.mu.Unlock()
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	m.HandleFunc("/api/setForceShutdown", d.auth(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.power = false
		d.mu.Unlock()
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	m.HandleFunc("/api/factoryReset", d.auth(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.token = ""
		d.autoStart, d.childLock = false, false
		d.mu.Unlock()
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	m.HandleFunc("/api/checkUpdate", d.auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("fs_version") == "1.0.3" && r.URL.Query().Get("lang") == "zh" {
			writeJSON(w, map[string]any{"status": "fail", "message": "已经是最新版本"})
			return
		}
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	m.HandleFunc("/api/firmwareUpdate", d.auth(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		if !d.updating {
			d.updating = true
			d.progress = 0
			go d.runUpdate()
		}
		d.mu.Unlock()
		writeJSON(w, map[string]any{"status": "ok"})
	}))
	return m
}

// runUpdate 模拟固件升级:进度 0→100,完成后版本号 +1。
func (d *device) runUpdate() {
	for {
		time.Sleep(400 * time.Millisecond)
		d.mu.Lock()
		d.progress += 5
		if d.progress >= 100 {
			d.progress = 100
			d.fw = "1.0.2"
			d.updating = false
			d.mu.Unlock()
			time.Sleep(5 * time.Second)
			d.mu.Lock()
			d.progress = 0
			d.mu.Unlock()
			return
		}
		d.mu.Unlock()
	}
}

func (d *device) handleLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.FormValue("password") != Password {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"status": "error", "msg": "password error"})
		return
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	d.mu.Lock()
	d.token = hex.EncodeToString(b)
	tk := d.token
	d.mu.Unlock()
	writeJSON(w, map[string]any{"status": "ok", "tK": tk})
}

func (d *device) handleInfo(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	writeJSON(w, map[string]any{
		"status": "ok",
		"oL":     true,
		"wN":     d.ssid,
		"wI":     d.addr,
		"wM":     "2C:3A:E8:35:F6:F2",
		"SN":     d.sn,
		"hN":     "HA-WBC-" + d.sn,
		"hP":     d.power,
		"hV":     "1.0.1",
		"hU":     "2025-08-11",
		"fV":     d.fw,
		"fU":     "2025-08-11",
		"fG":     d.progress,
		"mD":     "HA-WBC-2",
		"mT":     "WBC",
		"mF":     4194304,
	})
}

// auth 校验 Bearer 令牌。
func (d *device) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		got = strings.TrimSuffix(strings.TrimSpace(got), ";")
		d.mu.Lock()
		want := d.token
		d.mu.Unlock()
		if want == "" || got != want {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]any{"status": "error", "msg": "token invalid"})
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
