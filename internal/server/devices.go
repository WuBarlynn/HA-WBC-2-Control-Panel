package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"ha-wbc-console/internal/store"
	"ha-wbc-console/internal/wbc"
)

// publicDevice 返回给前端的设备信息(不含密码与设备令牌)。
type publicDevice struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Addr      string    `json:"addr"`
	AutoStart *bool     `json:"autoStart"`
	ChildLock *bool     `json:"childLock"`
	CreatedAt time.Time `json:"createdAt"`
}

func toPublic(d store.Device) publicDevice {
	return publicDevice{
		ID:        d.ID,
		Name:      d.Name,
		Addr:      d.Addr,
		AutoStart: d.AutoStart,
		ChildLock: d.ChildLock,
		CreatedAt: d.CreatedAt,
	}
}

var addrPattern = regexp.MustCompile(`^[0-9a-zA-Z.\-]+(:\d{1,5})?$`)

func validateDeviceInput(name, addr string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("设备名称不能为空")
	}
	if !addrPattern.MatchString(addr) {
		return errors.New("设备地址格式不正确,应为 IP 或 IP:端口")
	}
	return nil
}

// ---- 设备 CRUD ----

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devs := s.store.Devices()
	out := make([]publicDevice, 0, len(devs))
	for _, d := range devs {
		out = append(out, toPublic(d))
	}
	ok(w, out)
}

func (s *Server) handleAddDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Addr     string `json:"addr"`
		Password string `json:"password"`
	}
	if err := readBody(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	body.Addr = strings.TrimSpace(body.Addr)
	if err := validateDeviceInput(body.Name, body.Addr); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	dev, err := s.store.AddDevice(strings.TrimSpace(body.Name), body.Addr, body.Password)
	if err != nil {
		fail(w, http.StatusConflict, err.Error())
		return
	}
	s.syncHomeKit()
	ok(w, toPublic(dev))
}

func (s *Server) handleUpdateDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Addr     string `json:"addr"`
		Password string `json:"password"` // 为空表示不修改
	}
	if err := readBody(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	body.Addr = strings.TrimSpace(body.Addr)
	if err := validateDeviceInput(body.Name, body.Addr); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	dev, err := s.store.UpdateDevice(r.PathValue("id"), strings.TrimSpace(body.Name), body.Addr, body.Password)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusNotFound, err.Error())
			return
		}
		fail(w, http.StatusConflict, err.Error())
		return
	}
	s.syncHomeKit()
	ok(w, toPublic(dev))
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteDevice(r.PathValue("id")); err != nil {
		fail(w, http.StatusNotFound, err.Error())
		return
	}
	s.syncHomeKit()
	ok(w, nil)
}

func (s *Server) syncHomeKit() {
	if s.homekit == nil {
		return
	}
	if err := s.homekit.SyncDevices(); err != nil {
		// 设备数据已经成功保存；桥接异常通过 HomeKit 状态接口展示，
		// 不应让前端误以为设备 CRUD 失败。
		log.Printf("[homekit] 同步设备列表失败: %v", err)
	}
}

// handleTestDevice 测试设备连通性与密码正确性。
func (s *Server) handleTestDevice(w http.ResponseWriter, r *http.Request) {
	dev, found := s.store.Device(r.PathValue("id"))
	if !found {
		fail(w, http.StatusNotFound, "设备不存在")
		return
	}
	status, err := s.wbc.GetConnectStatus(dev.Addr)
	if err != nil {
		fail(w, http.StatusBadGateway, "设备无法连接: "+err.Error())
		return
	}
	token, err := s.wbc.Login(dev.Addr, dev.Password)
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	s.store.SetDeviceToken(dev.ID, token)
	ok(w, map[string]any{"status": status, "loginOk": true})
}

// ---- 设备操作代理 ----

// deviceHandler 将 {id} 解析为设备后调用 op。
func (s *Server) deviceHandler(op func(w http.ResponseWriter, r *http.Request, dev store.Device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dev, found := s.store.Device(r.PathValue("id"))
		if !found {
			fail(w, http.StatusNotFound, "设备不存在")
			return
		}
		op(w, r, dev)
	}
}

// deviceCall 确保持有有效设备令牌后调用 fn;令牌失效时自动重新登录并重试一次。
func (s *Server) deviceCall(dev store.Device, fn func(token string) (map[string]any, error)) (map[string]any, error) {
	token := dev.Token
	if token == "" {
		t, err := s.wbc.Login(dev.Addr, dev.Password)
		if err != nil {
			return nil, err
		}
		s.store.SetDeviceToken(dev.ID, t)
		token = t
	}
	res, err := fn(token)
	var de *wbc.DeviceError
	if err != nil && errors.As(err, &de) {
		// 设备有应答但拒绝,多半是令牌过期:重新登录再试一次
		t, loginErr := s.wbc.Login(dev.Addr, dev.Password)
		if loginErr != nil {
			return nil, loginErr
		}
		s.store.SetDeviceToken(dev.ID, t)
		return fn(t)
	}
	return res, err
}

// proxyErr 将设备调用错误翻译为 HTTP 响应。
func proxyErr(w http.ResponseWriter, err error) {
	var de *wbc.DeviceError
	if errors.As(err, &de) {
		fail(w, http.StatusBadGateway, err.Error())
		return
	}
	fail(w, http.StatusGatewayTimeout, err.Error())
}

func (s *Server) opStatus(w http.ResponseWriter, r *http.Request, dev store.Device) {
	res, err := s.wbc.GetConnectStatus(dev.Addr)
	if err != nil {
		proxyErr(w, err)
		return
	}
	ok(w, res)
}

func (s *Server) opInfo(w http.ResponseWriter, r *http.Request, dev store.Device) {
	res, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.GetDeviceInfo(dev.Addr, t)
	})
	if err != nil {
		proxyErr(w, err)
		return
	}
	ok(w, res)
}

func (s *Server) opDeviceState(w http.ResponseWriter, r *http.Request, dev store.Device) {
	res, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.GetDeviceState(dev.Addr, t)
	})
	if err != nil {
		proxyErr(w, err)
		return
	}
	ok(w, res)
}

// readState 读取 {"state": bool} 请求体。
func readState(r *http.Request) (bool, error) {
	var body struct {
		State *bool `json:"state"`
	}
	if err := readBody(r, &body); err != nil {
		return false, err
	}
	if body.State == nil {
		return false, errors.New("缺少 state 参数")
	}
	return *body.State, nil
}

func (s *Server) opPower(w http.ResponseWriter, r *http.Request, dev store.Device) {
	state, err := readState(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.SetPowerState(dev.Addr, t, state)
	}); err != nil {
		proxyErr(w, err)
		return
	}
	action := "开机"
	if !state {
		action = "关机"
	}
	ok(w, map[string]any{"message": fmt.Sprintf("已发送%s指令", action)})
}

func (s *Server) opRestart(w http.ResponseWriter, r *http.Request, dev store.Device) {
	if _, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.Restart(dev.Addr, t)
	}); err != nil {
		proxyErr(w, err)
		return
	}
	ok(w, map[string]any{"message": "开机卡正在重启"})
}

func (s *Server) opAutoStart(w http.ResponseWriter, r *http.Request, dev store.Device) {
	state, err := readState(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.SetAutoStartState(dev.Addr, t, state)
	}); err != nil {
		proxyErr(w, err)
		return
	}
	s.store.SetDeviceFlag(dev.ID, "autoStart", state)
	ok(w, nil)
}

func (s *Server) opChildLock(w http.ResponseWriter, r *http.Request, dev store.Device) {
	state, err := readState(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.SetChildLockState(dev.Addr, t, state)
	}); err != nil {
		proxyErr(w, err)
		return
	}
	s.store.SetDeviceFlag(dev.ID, "childLock", state)
	ok(w, nil)
}

func (s *Server) opForceShutdown(w http.ResponseWriter, r *http.Request, dev store.Device) {
	if _, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.SetForceShutdown(dev.Addr, t)
	}); err != nil {
		proxyErr(w, err)
		return
	}
	ok(w, map[string]any{"message": "已发送强制关机指令"})
}

func (s *Server) opSetWiFi(w http.ResponseWriter, r *http.Request, dev store.Device) {
	var body struct {
		SSID     string `json:"ssid"`
		Password string `json:"password"`
	}
	if err := readBody(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(body.SSID) == "" {
		fail(w, http.StatusBadRequest, "WiFi 名称不能为空")
		return
	}
	if _, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.SetWiFi(dev.Addr, t, body.SSID, body.Password)
	}); err != nil {
		proxyErr(w, err)
		return
	}
	ok(w, map[string]any{"message": "WiFi 配置已下发,设备可能会重新联网"})
}

func (s *Server) opWifiList(w http.ResponseWriter, r *http.Request, dev store.Device) {
	res, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.GetWifiList(dev.Addr, t)
	})
	if err != nil {
		proxyErr(w, err)
		return
	}
	ok(w, res)
}

func (s *Server) opCheckUpdate(w http.ResponseWriter, r *http.Request, dev store.Device) {
	fsVersion := r.URL.Query().Get("fs_version")
	if fsVersion == "" {
		fsVersion = "1.0.3"
	}
	res, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.CheckUpdate(dev.Addr, t, fsVersion)
	})
	if err != nil {
		proxyErr(w, err)
		return
	}
	ok(w, res)
}

func (s *Server) opUpdateProgress(w http.ResponseWriter, r *http.Request, dev store.Device) {
	res, err := s.wbc.GetUpdateProgress(dev.Addr)
	if err != nil {
		proxyErr(w, err)
		return
	}
	ok(w, res)
}

func (s *Server) opFirmwareUpdate(w http.ResponseWriter, r *http.Request, dev store.Device) {
	if _, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.FirmwareUpdate(dev.Addr, t)
	}); err != nil {
		proxyErr(w, err)
		return
	}
	ok(w, map[string]any{"message": "固件更新已开始"})
}

func (s *Server) opFactoryReset(w http.ResponseWriter, r *http.Request, dev store.Device) {
	if _, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
		return s.wbc.FactoryReset(dev.Addr, t)
	}); err != nil {
		proxyErr(w, err)
		return
	}
	s.store.SetDeviceToken(dev.ID, "")
	ok(w, map[string]any{"message": "设备已恢复出厂设置"})
}

// ---- 仪表盘聚合 ----

type overviewItem struct {
	Device      publicDevice   `json:"device"`
	Online      bool           `json:"online"`
	Status      map[string]any `json:"status,omitempty"`
	Info        map[string]any `json:"info,omitempty"`
	DeviceState map[string]any `json:"deviceState,omitempty"`
	Error       string         `json:"error,omitempty"`
}

// handleOverview 并发抓取全部设备的连接状态与详细信息。
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	devs := s.store.Devices()
	items := make([]overviewItem, len(devs))
	var wg sync.WaitGroup
	for i, dev := range devs {
		wg.Add(1)
		go func(i int, dev store.Device) {
			defer wg.Done()
			item := overviewItem{Device: toPublic(dev)}
			status, err := s.wbc.GetConnectStatus(dev.Addr)
			if err != nil {
				item.Error = "设备离线或无法连接"
				items[i] = item
				return
			}
			item.Online = true
			item.Status = status
			info, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
				return s.wbc.GetDeviceInfo(dev.Addr, t)
			})
			if err != nil {
				item.Error = err.Error()
			} else {
				item.Info = info
			}
			deviceState, err := s.deviceCall(dev, func(t string) (map[string]any, error) {
				return s.wbc.GetDeviceState(dev.Addr, t)
			})
			if err != nil {
				if item.Error == "" {
					item.Error = err.Error()
				}
			} else {
				item.DeviceState = deviceState
			}
			items[i] = item
		}(i, dev)
	}
	wg.Wait()
	sort.SliceStable(items, func(a, b int) bool {
		return items[a].Device.CreatedAt.Before(items[b].Device.CreatedAt)
	})
	ok(w, items)
}
