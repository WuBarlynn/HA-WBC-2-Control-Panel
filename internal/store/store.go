// Package store 提供基于 JSON 文件的持久化:管理员密码哈希与开机卡设备列表。
package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const pbkdf2Iterations = 120000

var (
	ErrNotFound      = errors.New("设备不存在")
	ErrBadPassword   = errors.New("密码错误")
	ErrAlreadySetup  = errors.New("系统已初始化")
	ErrNotInitialized = errors.New("系统尚未初始化")
)

// Device 一张开机卡的配置与缓存状态。
type Device struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Addr     string `json:"addr"`     // 设备 IP(可带端口)
	Password string `json:"password"` // 设备 WiFi 密码,用于登录设备
	Token    string `json:"token,omitempty"`
	// 设备 API 不提供读取接口,记录最近一次设置的值
	AutoStart *bool     `json:"autoStart,omitempty"`
	ChildLock *bool     `json:"childLock,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// Passkey 一条已注册的通行密钥(WebAuthn 凭证)。
type Passkey struct {
	ID         string    `json:"id"` // 凭证 ID(base64url)
	Name       string    `json:"name"`
	RPID       string    `json:"rpId"` // 注册时绑定的域名
	Alg        int64     `json:"alg"`
	PublicKey  []byte    `json:"publicKey"` // COSE 公钥原始字节
	SignCount  uint32    `json:"signCount"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt,omitzero"`
}

type persisted struct {
	AdminHash  string     `json:"adminHash"`
	UserHandle []byte     `json:"userHandle,omitempty"` // WebAuthn 用户句柄
	Devices    []*Device  `json:"devices"`
	Passkeys   []*Passkey `json:"passkeys,omitempty"`
}

// Store 线程安全的 JSON 文件存储。
type Store struct {
	mu   sync.RWMutex
	path string
	data persisted
}

// Open 读取(或准备创建)指定路径的数据文件。
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("读取数据文件失败: %w", err)
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("数据文件格式错误: %w", err)
	}
	return s, nil
}

// save 将数据原子写入磁盘,调用方需持有写锁。
func (s *Store) save() error {
	b, err := json.MarshalIndent(&s.data, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ---- 管理员密码 ----

// Initialized 是否已设置管理员密码。
func (s *Store) Initialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.AdminHash != ""
}

// SetupAdmin 首次设置管理员密码。
func (s *Store) SetupAdmin(password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.AdminHash != "" {
		return ErrAlreadySetup
	}
	s.data.AdminHash = hashPassword(password)
	return s.save()
}

// CheckAdmin 校验管理员密码。
func (s *Store) CheckAdmin(password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.AdminHash == "" {
		return false
	}
	return verifyPassword(s.data.AdminHash, password)
}

// ChangeAdmin 修改管理员密码。
func (s *Store) ChangeAdmin(oldPassword, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.AdminHash == "" {
		return ErrNotInitialized
	}
	if !verifyPassword(s.data.AdminHash, oldPassword) {
		return ErrBadPassword
	}
	s.data.AdminHash = hashPassword(newPassword)
	return s.save()
}

// ---- 设备管理 ----

// Devices 返回全部设备的副本。
func (s *Store) Devices() []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Device, 0, len(s.data.Devices))
	for _, d := range s.data.Devices {
		out = append(out, *d)
	}
	return out
}

// Device 按 ID 查找设备。
func (s *Store) Device(id string) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.data.Devices {
		if d.ID == id {
			return *d, true
		}
	}
	return Device{}, false
}

// AddDevice 添加设备。
func (s *Store) AddDevice(name, addr, password string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.data.Devices {
		if d.Addr == addr {
			return Device{}, fmt.Errorf("设备地址 %s 已存在(%s)", addr, d.Name)
		}
	}
	dev := &Device{
		ID:        randomID(),
		Name:      name,
		Addr:      addr,
		Password:  password,
		CreatedAt: time.Now(),
	}
	s.data.Devices = append(s.data.Devices, dev)
	if err := s.save(); err != nil {
		s.data.Devices = s.data.Devices[:len(s.data.Devices)-1]
		return Device{}, err
	}
	return *dev, nil
}

// UpdateDevice 更新设备信息;password 为空表示保持不变。
func (s *Store) UpdateDevice(id, name, addr, password string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.data.Devices {
		if d.ID != id {
			continue
		}
		for _, other := range s.data.Devices {
			if other.ID != id && other.Addr == addr {
				return Device{}, fmt.Errorf("设备地址 %s 已存在(%s)", addr, other.Name)
			}
		}
		if d.Addr != addr {
			d.Token = "" // 地址变化,令牌失效
		}
		d.Name = name
		d.Addr = addr
		if password != "" {
			d.Password = password
			d.Token = ""
		}
		if err := s.save(); err != nil {
			return Device{}, err
		}
		return *d, nil
	}
	return Device{}, ErrNotFound
}

// DeleteDevice 删除设备。
func (s *Store) DeleteDevice(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, d := range s.data.Devices {
		if d.ID == id {
			s.data.Devices = append(s.data.Devices[:i], s.data.Devices[i+1:]...)
			return s.save()
		}
	}
	return ErrNotFound
}

// SetDeviceToken 缓存设备登录令牌。
func (s *Store) SetDeviceToken(id, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.data.Devices {
		if d.ID == id {
			d.Token = token
			_ = s.save()
			return
		}
	}
}

// SetDeviceFlag 记录最近一次设置的开关值,flag 取 "autoStart" 或 "childLock"。
func (s *Store) SetDeviceFlag(id, flag string, v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.data.Devices {
		if d.ID == id {
			val := v
			switch flag {
			case "autoStart":
				d.AutoStart = &val
			case "childLock":
				d.ChildLock = &val
			}
			_ = s.save()
			return
		}
	}
}

// ---- 通行密钥 ----

// EnsureUserHandle 返回 WebAuthn 用户句柄,首次调用时生成并持久化。
func (s *Store) EnsureUserHandle() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.UserHandle) > 0 {
		out := make([]byte, len(s.data.UserHandle))
		copy(out, s.data.UserHandle)
		return out, nil
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	s.data.UserHandle = b
	if err := s.save(); err != nil {
		s.data.UserHandle = nil
		return nil, err
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

// Passkeys 返回全部通行密钥的副本。
func (s *Store) Passkeys() []Passkey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Passkey, 0, len(s.data.Passkeys))
	for _, p := range s.data.Passkeys {
		out = append(out, *p)
	}
	return out
}

// PasskeysForRP 返回绑定到指定 rpID 的通行密钥。
func (s *Store) PasskeysForRP(rpID string) []Passkey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Passkey, 0)
	for _, p := range s.data.Passkeys {
		if p.RPID == rpID {
			out = append(out, *p)
		}
	}
	return out
}

// PasskeyByID 按凭证 ID 查找。
func (s *Store) PasskeyByID(id string) (Passkey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.data.Passkeys {
		if p.ID == id {
			return *p, true
		}
	}
	return Passkey{}, false
}

// AddPasskey 保存新的通行密钥。
func (s *Store) AddPasskey(pk Passkey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.data.Passkeys {
		if p.ID == pk.ID {
			return errors.New("该通行密钥已注册")
		}
	}
	cp := pk
	s.data.Passkeys = append(s.data.Passkeys, &cp)
	if err := s.save(); err != nil {
		s.data.Passkeys = s.data.Passkeys[:len(s.data.Passkeys)-1]
		return err
	}
	return nil
}

// DeletePasskey 删除通行密钥。
func (s *Store) DeletePasskey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.data.Passkeys {
		if p.ID == id {
			s.data.Passkeys = append(s.data.Passkeys[:i], s.data.Passkeys[i+1:]...)
			return s.save()
		}
	}
	return errors.New("通行密钥不存在")
}

// UpdatePasskeyUsage 更新签名计数与最近使用时间。
func (s *Store) UpdatePasskeyUsage(id string, signCount uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.data.Passkeys {
		if p.ID == id {
			p.SignCount = signCount
			p.LastUsedAt = time.Now()
			_ = s.save()
			return
		}
	}
}

// ---- 密码哈希(PBKDF2-HMAC-SHA256, 标准库实现) ----

func hashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := pbkdf2Key([]byte(password), salt, pbkdf2Iterations, 32)
	return fmt.Sprintf("pbkdf2:%d:%s:%s", pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(key))
}

func verifyPassword(stored, password string) bool {
	parts := strings.Split(stored, ":")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	var iter int
	if _, err := fmt.Sscanf(parts[1], "%d", &iter); err != nil || iter <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2Key([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// pbkdf2Key RFC 2898 密钥派生。
func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var blockBuf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(blockBuf[:], uint32(block))
		prf.Write(blockBuf[:])
		t := prf.Sum(nil)
		copy(u, t)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func randomID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
