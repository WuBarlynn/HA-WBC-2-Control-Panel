// Package wbc 实现 HA-WBC-2 局域网开机卡的 HTTP API 客户端。
package wbc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DeviceError 表示设备已应答但返回了错误(如令牌失效、参数错误)。
// 网络不可达等错误不属于 DeviceError。
type DeviceError struct {
	HTTPCode int
	Message  string
}

func (e *DeviceError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("设备返回错误(HTTP %d): %s", e.HTTPCode, e.Message)
	}
	return fmt.Sprintf("设备返回错误(HTTP %d)", e.HTTPCode)
}

// Client HA-WBC-2 设备客户端,可并发使用。
type Client struct {
	hc *http.Client
}

// New 创建客户端,超时较短以适配局域网设备。
func New() *Client {
	return &Client{hc: &http.Client{Timeout: 5 * time.Second}}
}

func (c *Client) do(method, addr, path, token string, form url.Values) (map[string]any, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, "http://"+addr+path, body)
	if err != nil {
		return nil, fmt.Errorf("请求构造失败: %w", err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("无法连接设备 %s: %w", addr, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, &DeviceError{HTTPCode: resp.StatusCode, Message: msg}
	}
	if st, _ := m["status"].(string); st != "ok" {
		msg, _ := m["msg"].(string)
		if msg == "" {
			msg, _ = m["message"].(string)
		}
		if msg == "" {
			msg = fmt.Sprintf("status=%v", m["status"])
		}
		return nil, &DeviceError{HTTPCode: resp.StatusCode, Message: msg}
	}
	if resp.StatusCode/100 != 2 {
		return nil, &DeviceError{HTTPCode: resp.StatusCode}
	}
	return m, nil
}

func boolForm(key string, v bool) url.Values {
	return url.Values{key: {fmt.Sprintf("%t", v)}}
}

// Login 用 WiFi 密码登录设备,返回访问令牌 tK。
func (c *Client) Login(addr, password string) (string, error) {
	m, err := c.do(http.MethodPost, addr, "/api/login", "", url.Values{"password": {password}})
	if err != nil {
		var de *DeviceError
		if ok := asDeviceError(err, &de); ok {
			return "", fmt.Errorf("设备登录失败,请检查 WiFi 密码: %w", err)
		}
		return "", err
	}
	tk, _ := m["tK"].(string)
	if tk == "" {
		return "", fmt.Errorf("设备未返回令牌")
	}
	return tk, nil
}

func asDeviceError(err error, target **DeviceError) bool {
	de, ok := err.(*DeviceError)
	if ok {
		*target = de
	}
	return ok
}

// GetConnectStatus 连接状态(无需认证)。
func (c *Client) GetConnectStatus(addr string) (map[string]any, error) {
	return c.do(http.MethodGet, addr, "/api/getConnectStatus", "", nil)
}

// GetUpdateProgress 固件更新进度(无需认证)。
func (c *Client) GetUpdateProgress(addr string) (map[string]any, error) {
	return c.do(http.MethodGet, addr, "/api/getUpdateProgress", "", nil)
}

// GetDeviceInfo 设备详细信息。
func (c *Client) GetDeviceInfo(addr, token string) (map[string]any, error) {
	return c.do(http.MethodGet, addr, "/api/getDeviceInfo", token, nil)
}

// GetDeviceState 获取温度、主机电源、来电自启与童锁状态。
func (c *Client) GetDeviceState(addr, token string) (map[string]any, error) {
	return c.do(http.MethodGet, addr, "/api/getDeviceState?lang=zh", token, nil)
}

// VerifyToken 校验令牌有效性。
func (c *Client) VerifyToken(addr, token string) error {
	_, err := c.do(http.MethodGet, addr, "/api/verifyToken", token, nil)
	return err
}

// SetWiFi 配置设备 WiFi。
func (c *Client) SetWiFi(addr, token, ssid, password string) (map[string]any, error) {
	return c.do(http.MethodPost, addr, "/api/setWiFi", token, url.Values{"ssid": {ssid}, "password": {password}})
}

// GetWifiList 扫描附近 WiFi。
func (c *Client) GetWifiList(addr, token string) (map[string]any, error) {
	return c.do(http.MethodGet, addr, "/api/getWifiList", token, nil)
}

// Restart 重启开机卡。
func (c *Client) Restart(addr, token string) (map[string]any, error) {
	return c.do(http.MethodPost, addr, "/api/restart", token, nil)
}

// SetPowerState 控制主机开机/关机。
func (c *Client) SetPowerState(addr, token string, on bool) (map[string]any, error) {
	return c.do(http.MethodPost, addr, "/api/setPowerState", token, boolForm("state", on))
}

// SetAutoStartState 设置来电自启动。
func (c *Client) SetAutoStartState(addr, token string, on bool) (map[string]any, error) {
	return c.do(http.MethodPost, addr, "/api/setAutoStartState", token, boolForm("state", on))
}

// SetChildLockState 设置童锁。
func (c *Client) SetChildLockState(addr, token string, on bool) (map[string]any, error) {
	return c.do(http.MethodPost, addr, "/api/setChildLockState", token, boolForm("state", on))
}

// SetForceShutdown 强制关机(长按电源效果)。
func (c *Client) SetForceShutdown(addr, token string) (map[string]any, error) {
	return c.do(http.MethodPost, addr, "/api/setForceShutdown", token, nil)
}

// FactoryReset 恢复出厂设置。
func (c *Client) FactoryReset(addr, token string) (map[string]any, error) {
	return c.do(http.MethodPost, addr, "/api/factoryReset", token, nil)
}

// CheckUpdate 检查固件更新。设备以 fail 返回“已经是最新版本”时按正常结果处理。
func (c *Client) CheckUpdate(addr, token, fsVersion string) (map[string]any, error) {
	path := "/api/checkUpdate?fs_version=" + url.QueryEscape(fsVersion) + "&lang=zh"
	res, err := c.do(http.MethodGet, addr, path, token, nil)
	if err != nil {
		var de *DeviceError
		if asDeviceError(err, &de) && strings.Contains(de.Message, "已经是最新版本") {
			return map[string]any{"status": "ok", "latest": true, "message": de.Message}, nil
		}
		return nil, err
	}
	return res, nil
}

// FirmwareUpdate 执行固件更新。
func (c *Client) FirmwareUpdate(addr, token string) (map[string]any, error) {
	return c.do(http.MethodPost, addr, "/api/firmwareUpdate", token, nil)
}
