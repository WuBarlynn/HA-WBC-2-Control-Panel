// Package server 实现控制台的 HTTP 服务:系统认证、设备管理与设备 API 代理。
package server

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"ha-wbc-console/internal/homekit"
	"ha-wbc-console/internal/store"
	"ha-wbc-console/internal/wbc"
	"ha-wbc-console/internal/webauthn"
)

// Server 控制台 HTTP 服务。
type Server struct {
	store      *store.Store
	wbc        *wbc.Client
	sessions   *sessions
	challenges *webauthn.Challenges
	homekit    *homekit.Manager
	mux        *http.ServeMux
}

// New 创建服务并注册路由,webFS 为前端静态资源根(已定位到 web 目录)。
func New(st *store.Store, webFS fs.FS, hk *homekit.Manager) *Server {
	s := &Server{
		store:      st,
		wbc:        wbc.New(),
		sessions:   newSessions(),
		challenges: webauthn.NewChallenges(),
		homekit:    hk,
		mux:        http.NewServeMux(),
	}

	// 公开接口
	s.mux.HandleFunc("GET /api/state", s.handleState)
	s.mux.HandleFunc("POST /api/setup", s.handleSetup)
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/passkey/login/begin", s.handlePasskeyLoginBegin)
	s.mux.HandleFunc("POST /api/passkey/login/finish", s.handlePasskeyLoginFinish)

	// 仅人类会话(禁止 API Token 自管密钥/改密/Passkey/HomeKit)
	s.mux.Handle("POST /api/logout", s.sessionOnly(s.handleLogout))
	s.mux.Handle("POST /api/password", s.sessionOnly(s.handleChangePassword))
	s.mux.Handle("GET /api/passkey/list", s.sessionOnly(s.handlePasskeyList))
	s.mux.Handle("POST /api/passkey/register/begin", s.sessionOnly(s.handlePasskeyRegisterBegin))
	s.mux.Handle("POST /api/passkey/register/finish", s.sessionOnly(s.handlePasskeyRegisterFinish))
	s.mux.Handle("DELETE /api/passkey/{id}", s.sessionOnly(s.handlePasskeyDelete))
	s.mux.Handle("GET /api/homekit", s.sessionOnly(s.handleHomeKitStatus))
	s.mux.Handle("PUT /api/homekit", s.sessionOnly(s.handleHomeKitConfigure))
	s.mux.Handle("POST /api/homekit/reset", s.sessionOnly(s.handleHomeKitReset))
	s.mux.Handle("GET /api/tokens", s.sessionOnly(s.handleListAPITokens))
	s.mux.Handle("POST /api/tokens", s.sessionOnly(s.handleCreateAPIToken))
	s.mux.Handle("DELETE /api/tokens/{id}", s.sessionOnly(s.handleDeleteAPIToken))

	// 读:会话或 scope=read 的 API Token
	s.mux.Handle("GET /api/devices", s.requireScope("read", s.handleListDevices))
	s.mux.Handle("GET /api/overview", s.requireScope("read", s.handleOverview))
	s.mux.Handle("GET /api/devices/{id}/status", s.requireScope("read", s.deviceHandler(s.opStatus)))
	s.mux.Handle("GET /api/devices/{id}/info", s.requireScope("read", s.deviceHandler(s.opInfo)))
	s.mux.Handle("GET /api/devices/{id}/device-state", s.requireScope("read", s.deviceHandler(s.opDeviceState)))
	s.mux.Handle("GET /api/devices/{id}/wifi-list", s.requireScope("read", s.deviceHandler(s.opWifiList)))
	s.mux.Handle("GET /api/devices/{id}/check-update", s.requireScope("read", s.deviceHandler(s.opCheckUpdate)))
	s.mux.Handle("GET /api/devices/{id}/update-progress", s.requireScope("read", s.deviceHandler(s.opUpdateProgress)))

	// 电源:会话或 scope=power
	s.mux.Handle("POST /api/devices/{id}/power", s.requireScope("power", s.deviceHandler(s.opPower)))
	s.mux.Handle("POST /api/devices/{id}/restart", s.requireScope("power", s.deviceHandler(s.opRestart)))
	s.mux.Handle("POST /api/devices/{id}/autostart", s.requireScope("power", s.deviceHandler(s.opAutoStart)))
	s.mux.Handle("POST /api/devices/{id}/childlock", s.requireScope("power", s.deviceHandler(s.opChildLock)))
	s.mux.Handle("POST /api/devices/{id}/force-shutdown", s.requireScope("power", s.deviceHandler(s.opForceShutdown)))

	// 设备 CRUD / 配网 / 固件 / 出厂 — 仅人类会话
	s.mux.Handle("POST /api/devices", s.sessionOnly(s.handleAddDevice))
	s.mux.Handle("PUT /api/devices/{id}", s.sessionOnly(s.handleUpdateDevice))
	s.mux.Handle("DELETE /api/devices/{id}", s.sessionOnly(s.handleDeleteDevice))
	s.mux.Handle("POST /api/devices/{id}/test", s.sessionOnly(s.handleTestDevice))
	s.mux.Handle("POST /api/devices/{id}/wifi", s.sessionOnly(s.deviceHandler(s.opSetWiFi)))
	s.mux.Handle("POST /api/devices/{id}/firmware-update", s.sessionOnly(s.deviceHandler(s.opFirmwareUpdate)))
	s.mux.Handle("POST /api/devices/{id}/factory-reset", s.sessionOnly(s.deviceHandler(s.opFactoryReset)))

	// 静态资源
	s.mux.Handle("/", http.FileServer(http.FS(webFS)))
	return s
}

// statusRecorder 记录响应状态码,用于日志过滤。
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

// ServeHTTP 精简访问日志:仅记录写操作(POST/PUT/DELETE)与出错的请求,
// 轮询类 GET 不记录,避免在存储有限的设备上产生大量日志。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-cache")
	}
	rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
	s.mux.ServeHTTP(rec, r)
	if strings.HasPrefix(r.URL.Path, "/api/") && (r.Method != http.MethodGet || rec.code >= 400) {
		log.Printf("%s %s -> %d (%s) %s", r.Method, r.URL.Path, rec.code, r.RemoteAddr, time.Since(start).Round(time.Millisecond))
	}
}

// ---- 中间件与响应助手 ----

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	tok := strings.TrimPrefix(h, "Bearer ")
	return strings.TrimSuffix(strings.TrimSpace(tok), ";")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func ok(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": data})
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

// readBody 解析 JSON 请求体。
func readBody(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return errors.New("请求体格式错误")
	}
	return nil
}

// ---- 系统认证 ----

// handleState 前端启动时查询:是否已初始化、当前会话是否有效、
// 以及当前访问主机名(rpID)下可用的通行密钥数量。
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	passkeys := 0
	rpID := ""
	if id, err := rpIDFromRequest(r); err == nil {
		rpID = id
		passkeys = len(s.store.PasskeysForRP(id))
	}
	ok(w, map[string]any{
		"initialized": s.store.Initialized(),
		"authed":      s.sessions.valid(bearerToken(r)),
		"passkeys":    passkeys,
		"rpId":        rpID,
	})
}

// handleSetup 首次初始化管理员密码,成功后直接返回会话令牌。
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := readBody(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(body.Password) < 6 {
		fail(w, http.StatusBadRequest, "密码长度至少 6 位")
		return
	}
	if err := s.store.SetupAdmin(body.Password); err != nil {
		fail(w, http.StatusConflict, err.Error())
		return
	}
	log.Printf("管理员密码已初始化")
	ok(w, map[string]any{"token": s.sessions.create()})
}

// handleLogin 管理员登录。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := readBody(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.store.Initialized() {
		fail(w, http.StatusConflict, "系统尚未初始化")
		return
	}
	if !s.store.CheckAdmin(body.Password) {
		time.Sleep(600 * time.Millisecond) // 减缓暴力破解
		fail(w, http.StatusUnauthorized, "密码错误")
		return
	}
	ok(w, map[string]any{"token": s.sessions.create()})
}

// handleLogout 注销当前会话。
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessions.revoke(bearerToken(r))
	ok(w, nil)
}

// handleChangePassword 修改管理员密码。
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := readBody(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(body.New) < 6 {
		fail(w, http.StatusBadRequest, "新密码长度至少 6 位")
		return
	}
	if err := s.store.ChangeAdmin(body.Old, body.New); err != nil {
		if errors.Is(err, store.ErrBadPassword) {
			fail(w, http.StatusUnauthorized, "原密码错误")
			return
		}
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, nil)
}
