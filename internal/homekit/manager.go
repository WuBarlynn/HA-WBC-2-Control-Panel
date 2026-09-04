// Package homekit 将控制台中的 HA-WBC-2 设备桥接到 Apple 家庭。
package homekit

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brutella/hap"
	"github.com/brutella/hap/accessory"
	"github.com/brutella/hap/characteristic"
	haplog "github.com/brutella/hap/log"
	"github.com/brutella/hap/service"

	"ha-wbc-console/internal/store"
	"ha-wbc-console/internal/wbc"
)

const (
	defaultName           = "HA-WBC-2 控制台"
	defaultPort           = 51826
	maxBridgedAccessories = 149
	stateTTL              = 2 * time.Second
)

var (
	pinPattern     = regexp.MustCompile(`^\d{8}$`)
	setupIDPattern = regexp.MustCompile(`^[0-9A-Z]{4}$`)
	hapLogOnce     sync.Once
)

// ConfigError 表示可由用户在设置页修正的配置错误。
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string { return e.Message }

// PortError 表示 HAP TCP 端口冲突。
type PortError struct {
	Port int
	Err  error
}

func (e *PortError) Error() string {
	return fmt.Sprintf("HomeKit 端口 %d 无法监听: %v", e.Port, e.Err)
}
func (e *PortError) Unwrap() error { return e.Err }

// Status 是设置页需要展示的桥接状态。
type Status struct {
	Enabled      bool   `json:"enabled"`
	Running      bool   `json:"running"`
	Paired       bool   `json:"paired"`
	PairingCount int    `json:"pairingCount"`
	Name         string `json:"name"`
	Pin          string `json:"pin"`
	Port         int    `json:"port"`
	SetupURI     string `json:"setupUri,omitempty"`
	DeviceCount  int    `json:"deviceCount"`
	Error        string `json:"error,omitempty"`
}

// Manager 管理 HAP 服务生命周期、设备组件与状态同步。
type Manager struct {
	mu          sync.Mutex
	store       *store.Store
	wbc         *wbc.Client
	version     string
	cfg         store.HomeKitConfig
	server      *hap.Server
	cancel      context.CancelFunc
	done        chan error
	pollDone    chan struct{}
	running     bool
	lastError   string
	preferredIP net.IP

	deviceLocksMu sync.Mutex
	deviceLocks   map[string]*sync.Mutex
}

// New 创建管理器并补齐首次使用所需的随机 PIN 与稳定 Setup ID。
func New(st *store.Store, version string) (*Manager, error) {
	cfg := st.HomeKitConfig()
	changed := false
	if strings.TrimSpace(cfg.Name) == "" {
		cfg.Name = defaultName
		changed = true
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		cfg.Port = defaultPort
		changed = true
	}
	cfg.Pin = normalizePin(cfg.Pin)
	if err := validatePin(cfg.Pin); err != nil {
		pin, genErr := randomPin()
		if genErr != nil {
			return nil, fmt.Errorf("生成 HomeKit PIN 失败: %w", genErr)
		}
		cfg.Pin = pin
		changed = true
	}
	cfg.SetupID = strings.ToUpper(strings.TrimSpace(cfg.SetupID))
	if !setupIDPattern.MatchString(cfg.SetupID) {
		id, genErr := randomSetupID()
		if genErr != nil {
			return nil, fmt.Errorf("生成 HomeKit Setup ID 失败: %w", genErr)
		}
		cfg.SetupID = id
		changed = true
	}
	if changed {
		if err := st.SetHomeKitConfig(cfg); err != nil {
			return nil, fmt.Errorf("保存 HomeKit 初始配置失败: %w", err)
		}
	}
	return &Manager{
		store:       st,
		wbc:         wbc.New(),
		version:     version,
		cfg:         cfg,
		deviceLocks: make(map[string]*sync.Mutex),
	}, nil
}

// Start 按持久化配置启动桥接服务；未启用时不执行任何操作。
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.Enabled || m.running {
		return nil
	}
	return m.startLocked()
}

// Close 停止桥接服务但保留“已启用”配置，供下次启动自动恢复。
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

// Configure 保存配置并按需重启桥接服务。
func (m *Manager) Configure(cfg store.HomeKitConfig, preferredIP net.IP) error {
	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.Pin = normalizePin(cfg.Pin)
	if cfg.Name == "" {
		return &ConfigError{Message: "HomeKit 桥名称不能为空"}
	}
	if len([]rune(cfg.Name)) > 64 {
		return &ConfigError{Message: "HomeKit 桥名称不能超过 64 个字符"}
	}
	if err := validatePin(cfg.Pin); err != nil {
		return &ConfigError{Message: err.Error()}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return &ConfigError{Message: "HomeKit 端口必须在 1 到 65535 之间"}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.preferredIP = append(net.IP(nil), preferredIP...)
	cfg.SetupID = m.cfg.SetupID
	if m.store.HomeKitPairingCount() > 0 && cfg.Pin != m.cfg.Pin {
		return &ConfigError{Message: "桥已配对；修改 PIN 前请先重置 HomeKit 配对"}
	}
	if cfg == m.cfg {
		if cfg.Enabled {
			m.stopLocked()
			return m.startLocked()
		}
		return nil
	}
	if err := m.store.SetHomeKitConfig(cfg); err != nil {
		return err
	}
	m.cfg = cfg
	m.stopLocked()
	if cfg.Enabled {
		if err := m.startLocked(); err != nil {
			return err
		}
	} else {
		m.lastError = ""
	}
	log.Printf("[homekit] 配置已更新: enabled=%t name=%q port=%d", cfg.Enabled, cfg.Name, cfg.Port)
	return nil
}

// SyncDevices 在设备增删改后重建桥配置；稳定的配件 ID 不会改变。
func (m *Manager) SyncDevices() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cfg.Enabled {
		return nil
	}
	m.stopLocked()
	return m.startLocked()
}

// ResetPairings 清除 Apple 家庭控制器授权并重新开放配对。
func (m *Manager) ResetPairings(preferredIP net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.preferredIP = append(net.IP(nil), preferredIP...)
	m.stopLocked()
	if err := m.store.ClearHomeKitPairings(); err != nil {
		return err
	}
	if m.cfg.Enabled {
		if err := m.startLocked(); err != nil {
			return err
		}
	}
	log.Printf("[homekit] Apple 家庭配对已重置")
	return nil
}

// Status 返回实时服务与配对状态。
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	pairings := m.store.HomeKitPairingCount()
	return Status{
		Enabled:      m.cfg.Enabled,
		Running:      m.running,
		Paired:       pairings > 0,
		PairingCount: pairings,
		Name:         m.cfg.Name,
		Pin:          formatPin(m.cfg.Pin),
		Port:         m.cfg.Port,
		SetupURI:     setupURI(m.cfg.Pin, m.cfg.SetupID),
		DeviceCount:  len(m.store.Devices()),
		Error:        m.lastError,
	}
}

func (m *Manager) startLocked() error {
	hapLogOnce.Do(func() {
		haplog.Info.SetOutput(os.Stderr)
	})
	addr := fmt.Sprintf(":%d", m.cfg.Port)
	probe, err := net.Listen("tcp", addr)
	if err != nil {
		portErr := &PortError{Port: m.cfg.Port, Err: err}
		m.lastError = portErr.Error()
		return portErr
	}
	_ = probe.Close()

	bridge := accessory.NewBridge(accessory.Info{
		Name:         homeKitServiceName(m.cfg.Name),
		SerialNumber: "HA-WBC-2-BRIDGE",
		Manufacturer: "WuBarlynn",
		Model:        "HA-WBC-2 Control Panel",
		Firmware:     m.version,
	})
	bridge.A.Id = 1

	devices := m.store.Devices()
	if len(devices) > maxBridgedAccessories {
		m.lastError = fmt.Sprintf("HomeKit 单桥最多支持 %d 台设备，当前为 %d 台", maxBridgedAccessories, len(devices))
		return errors.New(m.lastError)
	}
	accessories := make([]*accessory.A, 0, len(devices))
	bindings := make([]*deviceBinding, 0, len(devices))
	accessoryIDs := map[uint64]string{1: "bridge"}
	for _, dev := range devices {
		binding := m.newDeviceBinding(dev)
		aid := binding.accessory.A.Id
		if previous, exists := accessoryIDs[aid]; exists {
			m.lastError = fmt.Sprintf("设备 %s 与 %s 的 HomeKit 配件 ID 冲突", dev.ID, previous)
			return errors.New(m.lastError)
		}
		accessoryIDs[aid] = dev.ID
		accessories = append(accessories, binding.accessory.A)
		bindings = append(bindings, binding)
	}

	srv, err := hap.NewServer(m.store.HomeKitStore(), bridge.A, accessories...)
	if err != nil {
		m.lastError = err.Error()
		return fmt.Errorf("创建 HomeKit 桥失败: %w", err)
	}
	srv.Pin = m.cfg.Pin
	srv.SetupId = m.cfg.SetupID
	srv.Addr = addr
	ifaces, err := homeKitInterfaces(devices, m.preferredIP)
	if err != nil {
		m.lastError = err.Error()
		return err
	}
	srv.Ifaces = ifaces

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	pollDone := make(chan struct{})
	m.server = srv
	m.cancel = cancel
	m.done = done
	m.pollDone = pollDone
	m.running = false
	m.lastError = ""

	go func() {
		defer close(pollDone)
		m.poll(ctx, bindings)
	}()
	go func() {
		err := srv.ListenAndServe(ctx)
		if ctx.Err() != nil {
			err = nil
		}
		done <- err
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.server == srv {
			m.running = false
			if err != nil {
				m.lastError = err.Error()
				log.Printf("[homekit] 服务异常停止: %v", err)
			}
		}
	}()

	// HAP 库在 goroutine 内完成真正的 TCP 绑定和 mDNS 初始化；
	// 给立即失败留出反馈窗口，避免设置页过早报告“已启动”。
	select {
	case err := <-done:
		cancel()
		m.server = nil
		m.cancel = nil
		m.done = nil
		m.pollDone = nil
		if err == nil {
			err = errors.New("HomeKit 服务在启动阶段意外停止")
		}
		m.lastError = err.Error()
		return fmt.Errorf("启动 HomeKit 桥失败: %w", err)
	case <-time.After(250 * time.Millisecond):
		m.running = true
	}

	log.Printf("[homekit] 桥已启动: name=%q port=%d interfaces=%v devices=%d paired=%t", m.cfg.Name, m.cfg.Port, ifaces, len(devices), srv.IsPaired())
	return nil
}

type homeKitInterface struct {
	name    string
	network *net.IPNet
}

func homeKitServiceName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('_')
		}
	}
	serviceName := strings.Trim(b.String(), "-_")
	if serviceName == "" {
		return "HA-WBC-2_Bridge"
	}
	return serviceName
}

func homeKitInterfaces(devices []store.Device, preferredIP net.IP) ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("读取网络接口失败: %w", err)
	}

	var candidates []homeKitInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, network, err := net.ParseCIDR(addr.String())
			if err != nil || ip.To4() == nil || ip.IsLoopback() || !ip.IsPrivate() || ip.IsLinkLocalUnicast() {
				continue
			}
			candidates = append(candidates, homeKitInterface{name: iface.Name, network: network})
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("未找到可用于 HomeKit 的局域网接口")
	}
	return []string{selectHomeKitInterface(candidates, devices, preferredIP)}, nil
}

func selectHomeKitInterface(candidates []homeKitInterface, devices []store.Device, preferredIP net.IP) string {
	if preferredIP != nil {
		for _, candidate := range candidates {
			if candidate.network.Contains(preferredIP) {
				return candidate.name
			}
		}
	}
	for _, dev := range devices {
		host := dev.Addr
		if parsedHost, _, err := net.SplitHostPort(dev.Addr); err == nil {
			host = parsedHost
		}
		deviceIP := net.ParseIP(strings.Trim(host, "[]"))
		if deviceIP == nil {
			continue
		}
		for _, candidate := range candidates {
			if candidate.network.Contains(deviceIP) {
				return candidate.name
			}
		}
	}
	return candidates[len(candidates)-1].name
}

func (m *Manager) stopLocked() {
	if m.cancel == nil {
		m.running = false
		return
	}
	cancel, done, pollDone := m.cancel, m.done, m.pollDone
	m.cancel = nil
	m.done = nil
	m.pollDone = nil
	m.server = nil
	m.running = false
	cancel()

	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	for done != nil || pollDone != nil {
		select {
		case <-done:
			done = nil
		case <-pollDone:
			pollDone = nil
		case <-timer.C:
			log.Printf("[homekit] 等待桥接服务和设备轮询停止超时")
			return
		}
	}
}

type deviceState struct {
	power     bool
	autoStart bool
	childLock bool
	temp      float64
}

type deviceBinding struct {
	manager   *Manager
	deviceID  string
	accessory *accessory.Switch
	autoStart *service.Switch
	childLock *service.Switch
	temp      *service.TemperatureSensor

	refreshMu   sync.Mutex
	stateMu     sync.RWMutex
	state       deviceState
	lastRefresh time.Time
	lastErr     error
}

func (m *Manager) newDeviceBinding(dev store.Device) *deviceBinding {
	a := accessory.NewSwitch(accessory.Info{
		Name:         dev.Name,
		SerialNumber: dev.ID,
		Manufacturer: "SUMSG Inc.",
		Model:        "HA-WBC-2",
		Firmware:     m.version,
	})
	a.A.Id = accessoryID(dev.ID)
	a.Switch.Primary = true
	addServiceName(a.Switch.S, dev.Name+" 电源")

	autoStart := service.NewSwitch()
	addServiceName(autoStart.S, dev.Name+" 来电自启")
	autoStart.On.Description = "通电后自动启动主机"
	a.AddS(autoStart.S)

	childLock := service.NewSwitch()
	addServiceName(childLock.S, dev.Name+" 童锁")
	childLock.On.Description = "锁定开机卡实体按键"
	a.AddS(childLock.S)

	temp := service.NewTemperatureSensor()
	addServiceName(temp.S, dev.Name+" 温度")
	a.AddS(temp.S)

	b := &deviceBinding{
		manager:   m,
		deviceID:  dev.ID,
		accessory: a,
		autoStart: autoStart,
		childLock: childLock,
		temp:      temp,
	}

	a.Switch.On.OnSetRemoteValue(func(on bool) error {
		return m.setPower(dev.ID, on)
	})
	autoStart.On.OnSetRemoteValue(func(on bool) error {
		return m.setAutoStart(dev.ID, on)
	})
	childLock.On.OnSetRemoteValue(func(on bool) error {
		return m.setChildLock(dev.ID, on)
	})

	a.Switch.On.ValueRequestFunc = b.boolGetter(func(s deviceState) bool { return s.power })
	autoStart.On.ValueRequestFunc = b.boolGetter(func(s deviceState) bool { return s.autoStart })
	childLock.On.ValueRequestFunc = b.boolGetter(func(s deviceState) bool { return s.childLock })
	temp.CurrentTemperature.ValueRequestFunc = b.floatGetter(func(s deviceState) float64 { return s.temp })
	return b
}

func addServiceName(s *service.S, name string) {
	legacyName := characteristic.NewName()
	legacyName.SetValue(name)
	s.AddC(legacyName.C)
	configuredName := characteristic.NewConfiguredName()
	configuredName.SetValue(name)
	s.AddC(configuredName.C)
}

func (b *deviceBinding) boolGetter(selectValue func(deviceState) bool) func(*http.Request) (interface{}, int) {
	return func(req *http.Request) (interface{}, int) {
		if req == nil {
			return selectValue(b.currentState()), 0
		}
		state, err := b.refresh(false)
		if err != nil {
			return nil, hap.JsonStatusServiceCommunicationFailure
		}
		return selectValue(state), 0
	}
}

func (b *deviceBinding) floatGetter(selectValue func(deviceState) float64) func(*http.Request) (interface{}, int) {
	return func(req *http.Request) (interface{}, int) {
		if req == nil {
			return selectValue(b.currentState()), 0
		}
		state, err := b.refresh(false)
		if err != nil {
			return nil, hap.JsonStatusServiceCommunicationFailure
		}
		return selectValue(state), 0
	}
}

func (b *deviceBinding) currentState() deviceState {
	b.stateMu.RLock()
	defer b.stateMu.RUnlock()
	return b.state
}

func (b *deviceBinding) refresh(force bool) (deviceState, error) {
	b.refreshMu.Lock()
	defer b.refreshMu.Unlock()

	b.stateMu.RLock()
	if !force && !b.lastRefresh.IsZero() && time.Since(b.lastRefresh) < stateTTL {
		state, err := b.state, b.lastErr
		b.stateMu.RUnlock()
		return state, err
	}
	b.stateMu.RUnlock()

	state, err := b.manager.getState(b.deviceID)
	b.stateMu.Lock()
	b.lastRefresh = time.Now()
	b.lastErr = err
	if err == nil {
		b.state = state
	}
	current := b.state
	b.stateMu.Unlock()

	if err == nil {
		b.accessory.Switch.On.SetValue(state.power)
		b.autoStart.On.SetValue(state.autoStart)
		b.childLock.On.SetValue(state.childLock)
		b.temp.CurrentTemperature.SetValue(state.temp)
	}
	return current, err
}

func (m *Manager) poll(ctx context.Context, bindings []*deviceBinding) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		var wg sync.WaitGroup
		for _, binding := range bindings {
			wg.Add(1)
			go func(b *deviceBinding) {
				defer wg.Done()
				_, _ = b.refresh(true)
			}(binding)
		}
		wg.Wait()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) lockForDevice(id string) *sync.Mutex {
	m.deviceLocksMu.Lock()
	defer m.deviceLocksMu.Unlock()
	mu := m.deviceLocks[id]
	if mu == nil {
		mu = &sync.Mutex{}
		m.deviceLocks[id] = mu
	}
	return mu
}

func (m *Manager) deviceCall(id string, fn func(store.Device, string) (map[string]any, error)) (map[string]any, error) {
	mu := m.lockForDevice(id)
	mu.Lock()
	defer mu.Unlock()

	dev, ok := m.store.Device(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	token := dev.Token
	if token == "" {
		newToken, err := m.wbc.Login(dev.Addr, dev.Password)
		if err != nil {
			return nil, err
		}
		m.store.SetDeviceToken(id, newToken)
		token = newToken
	}
	result, err := fn(dev, token)
	var deviceErr *wbc.DeviceError
	if err != nil && errors.As(err, &deviceErr) {
		newToken, loginErr := m.wbc.Login(dev.Addr, dev.Password)
		if loginErr != nil {
			return nil, loginErr
		}
		m.store.SetDeviceToken(id, newToken)
		return fn(dev, newToken)
	}
	return result, err
}

func (m *Manager) getState(id string) (deviceState, error) {
	result, err := m.deviceCall(id, func(dev store.Device, token string) (map[string]any, error) {
		return m.wbc.GetDeviceState(dev.Addr, token)
	})
	if err != nil {
		return deviceState{}, err
	}
	power, powerOK := result["pW"].(bool)
	autoStart, autoOK := result["aS"].(bool)
	childLock, childOK := result["cL"].(bool)
	temp, tempOK := result["tP"].(float64)
	if !powerOK || !autoOK || !childOK || !tempOK {
		return deviceState{}, errors.New("设备状态响应缺少 HomeKit 所需字段")
	}
	return deviceState{power: power, autoStart: autoStart, childLock: childLock, temp: temp}, nil
}

func (m *Manager) setPower(id string, on bool) error {
	_, err := m.deviceCall(id, func(dev store.Device, token string) (map[string]any, error) {
		return m.wbc.SetPowerState(dev.Addr, token, on)
	})
	return err
}

func (m *Manager) setAutoStart(id string, on bool) error {
	_, err := m.deviceCall(id, func(dev store.Device, token string) (map[string]any, error) {
		return m.wbc.SetAutoStartState(dev.Addr, token, on)
	})
	if err == nil {
		m.store.SetDeviceFlag(id, "autoStart", on)
	}
	return err
}

func (m *Manager) setChildLock(id string, on bool) error {
	_, err := m.deviceCall(id, func(dev store.Device, token string) (map[string]any, error) {
		return m.wbc.SetChildLockState(dev.Addr, token, on)
	})
	if err == nil {
		m.store.SetDeviceFlag(id, "childLock", on)
	}
	return err
}

func normalizePin(pin string) string {
	return strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(pin))
}

func validatePin(pin string) error {
	if !pinPattern.MatchString(pin) {
		return errors.New("HomeKit PIN 必须是 8 位数字")
	}
	if hap.InvalidPins[pin] {
		return errors.New("该 HomeKit PIN 过于简单，请换一个")
	}
	return nil
}

func randomPin() (string, error) {
	limit := big.NewInt(100000000)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		pin := fmt.Sprintf("%08d", n.Int64())
		if validatePin(pin) == nil {
			return pin, nil
		}
	}
}

func randomSetupID() (string, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	out := make([]byte, 4)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}

func formatPin(pin string) string {
	if len(pin) != 8 {
		return pin
	}
	return pin[:3] + "-" + pin[3:5] + "-" + pin[5:]
}

// setupURI 生成 Apple 家庭二维码中的 X-HM:// payload。
func setupURI(pin, setupID string) string {
	code, err := strconv.ParseUint(normalizePin(pin), 10, 27)
	if err != nil || !setupIDPattern.MatchString(setupID) {
		return ""
	}
	const (
		categoryBridge = uint64(2)
		flagIP         = uint64(2)
	)
	payload := (categoryBridge << 31) | (flagIP << 27) | code
	encoded := strings.ToUpper(strconv.FormatUint(payload, 36))
	encoded = strings.Repeat("0", 9-len(encoded)) + encoded
	return "X-HM://" + encoded + setupID
}

func accessoryID(id string) uint64 {
	const maxAccessoryID = uint64(1<<31 - 1)
	value, err := strconv.ParseUint(id, 16, 64)
	if err != nil {
		value = 0
		for _, r := range id {
			value = value*131 + uint64(r)
		}
	}
	return value%(maxAccessoryID-1) + 2
}
