package server

import (
	"encoding/base64"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"ha-wbc-console/internal/store"
	"ha-wbc-console/internal/webauthn"
)

const rpDisplayName = "HA-WBC-2 开机卡控制台"

var b64u = base64.RawURLEncoding

// rpIDFromRequest 从请求 Host 推导 rpID(主机名)。
// WebAuthn 规范要求 rpID 为域名,浏览器对 IP 来源一律拒绝,这里提前给出明确提示。
func rpIDFromRequest(r *http.Request) (string, error) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", errors.New("无法确定访问主机名")
	}
	if net.ParseIP(host) != nil {
		return "", errors.New("通行密钥无法在 IP 地址下使用,请通过 localhost 或域名访问")
	}
	return strings.ToLower(host), nil
}

// publicPasskey 返回给前端的通行密钥信息。
type publicPasskey struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	RPID       string    `json:"rpId"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
}

func toPublicPasskey(p store.Passkey) publicPasskey {
	return publicPasskey{
		ID:         p.ID,
		Name:       p.Name,
		RPID:       p.RPID,
		CreatedAt:  p.CreatedAt,
		LastUsedAt: p.LastUsedAt,
	}
}

// handlePasskeyList 列出全部通行密钥。
func (s *Server) handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	pks := s.store.Passkeys()
	out := make([]publicPasskey, 0, len(pks))
	for _, p := range pks {
		out = append(out, toPublicPasskey(p))
	}
	ok(w, out)
}

// handlePasskeyDelete 删除通行密钥。
func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeletePasskey(r.PathValue("id")); err != nil {
		fail(w, http.StatusNotFound, err.Error())
		return
	}
	log.Printf("通行密钥已删除")
	ok(w, nil)
}

// handlePasskeyRegisterBegin 开始注册(需已登录)。
func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	rpID, err := rpIDFromRequest(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	handle, err := s.store.EnsureUserHandle()
	if err != nil {
		fail(w, http.StatusInternalServerError, "生成用户句柄失败: "+err.Error())
		return
	}
	var exclude []string
	for _, p := range s.store.PasskeysForRP(rpID) {
		exclude = append(exclude, p.ID)
	}
	challenge := s.challenges.New("register")
	ok(w, map[string]any{
		"publicKey": webauthn.CreationOptions(rpID, rpDisplayName, handle, "admin", challenge, exclude),
	})
}

// handlePasskeyRegisterFinish 完成注册并保存凭证(需已登录)。
func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	rpID, err := rpIDFromRequest(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	var body struct {
		Name              string `json:"name"`
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	}
	if err := readBody(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	cdj, err1 := b64u.DecodeString(body.ClientDataJSON)
	att, err2 := b64u.DecodeString(body.AttestationObject)
	if err1 != nil || err2 != nil {
		fail(w, http.StatusBadRequest, "凭证数据编码错误")
		return
	}
	challenge, err := webauthn.ClientDataChallenge(cdj)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.challenges.Consume("register", challenge) {
		fail(w, http.StatusBadRequest, "挑战无效或已过期,请重试")
		return
	}
	cred, err := webauthn.FinishRegistration(rpID, challenge, cdj, att)
	if err != nil {
		fail(w, http.StatusBadRequest, "注册校验失败: "+err.Error())
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "通行密钥"
	}
	if len([]rune(name)) > 30 {
		name = string([]rune(name)[:30])
	}
	pk := store.Passkey{
		ID:        b64u.EncodeToString(cred.ID),
		Name:      name,
		RPID:      rpID,
		Alg:       cred.Alg,
		PublicKey: cred.PublicKeyCOSE,
		SignCount: cred.SignCount,
		CreatedAt: time.Now(),
	}
	if err := s.store.AddPasskey(pk); err != nil {
		fail(w, http.StatusConflict, err.Error())
		return
	}
	log.Printf("通行密钥已注册: %s (rpID=%s)", name, rpID)
	ok(w, toPublicPasskey(pk))
}

// handlePasskeyLoginBegin 开始通行密钥登录(公开)。
func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	rpID, err := rpIDFromRequest(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	pks := s.store.PasskeysForRP(rpID)
	if len(pks) == 0 {
		fail(w, http.StatusNotFound, "当前访问地址("+rpID+")下未注册通行密钥,请先用密码登录后在系统设置中添加")
		return
	}
	allow := make([]string, 0, len(pks))
	for _, p := range pks {
		allow = append(allow, p.ID)
	}
	challenge := s.challenges.New("login")
	ok(w, map[string]any{
		"publicKey": webauthn.RequestOptions(rpID, challenge, allow),
	})
}

// handlePasskeyLoginFinish 校验断言并发放会话令牌(公开)。
func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	rpID, err := rpIDFromRequest(r)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	var body struct {
		ID                string `json:"id"`
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
	}
	if err := readBody(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	cdj, err1 := b64u.DecodeString(body.ClientDataJSON)
	authData, err2 := b64u.DecodeString(body.AuthenticatorData)
	sig, err3 := b64u.DecodeString(body.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		fail(w, http.StatusBadRequest, "凭证数据编码错误")
		return
	}
	challenge, err := webauthn.ClientDataChallenge(cdj)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.challenges.Consume("login", challenge) {
		fail(w, http.StatusUnauthorized, "挑战无效或已过期,请重试")
		return
	}
	pk, found := s.store.PasskeyByID(body.ID)
	if !found || pk.RPID != rpID {
		time.Sleep(600 * time.Millisecond)
		fail(w, http.StatusUnauthorized, "未知的通行密钥")
		return
	}
	newCount, err := webauthn.FinishLogin(rpID, challenge, pk.PublicKey, cdj, authData, sig)
	if err != nil {
		time.Sleep(600 * time.Millisecond)
		log.Printf("通行密钥登录失败: %v (%s)", err, r.RemoteAddr)
		fail(w, http.StatusUnauthorized, "通行密钥校验失败: "+err.Error())
		return
	}
	// 签名计数回退可能意味着凭证被克隆,记录但不阻断(多数平台认证器恒为 0)
	if pk.SignCount > 0 && newCount > 0 && newCount <= pk.SignCount {
		log.Printf("警告: 通行密钥 %s 签名计数异常(%d -> %d)", pk.Name, pk.SignCount, newCount)
	}
	s.store.UpdatePasskeyUsage(pk.ID, newCount)
	log.Printf("通行密钥登录成功: %s (%s)", pk.Name, r.RemoteAddr)
	ok(w, map[string]any{"token": s.sessions.create()})
}
