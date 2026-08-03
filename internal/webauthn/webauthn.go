// Package webauthn 实现通行密钥(WebAuthn)注册与认证所需的最小服务端子集,
// 仅使用标准库:注册采用 attestation=none,算法支持 ES256 与 RS256。
package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// COSE 算法标识
	AlgES256 int64 = -7
	AlgRS256 int64 = -257

	challengeTTL = 2 * time.Minute

	// authenticator data 标志位
	flagUserPresent    byte = 0x01
	flagAttestedCred   byte = 0x40
	minAuthDataLen          = 37
	maxCredentialIDLen      = 1024
)

var b64 = base64.RawURLEncoding

// ---------- 挑战管理 ----------

// Challenges 一次性挑战管理:随机 32 字节、2 分钟过期、区分用途。
type Challenges struct {
	mu sync.Mutex
	m  map[string]chalInfo
}

type chalInfo struct {
	purpose string
	expires time.Time
}

func NewChallenges() *Challenges {
	return &Challenges{m: make(map[string]chalInfo)}
}

// New 生成一个用于指定用途("register"/"login")的挑战,返回 base64url 编码。
func (c *Challenges) New(purpose string) string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	s := b64.EncodeToString(buf)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, v := range c.m {
		if now.After(v.expires) {
			delete(c.m, k)
		}
	}
	c.m[s] = chalInfo{purpose: purpose, expires: now.Add(challengeTTL)}
	return s
}

// Consume 校验并销毁挑战(单次使用)。
func (c *Challenges) Consume(purpose, s string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, ok := c.m[s]
	if !ok {
		return false
	}
	delete(c.m, s)
	return info.purpose == purpose && time.Now().Before(info.expires)
}

// ---------- COSE 公钥 ----------

// PublicKey 已解析的凭证公钥。
type PublicKey struct {
	Alg int64
	ec  *ecdsa.PublicKey
	rsa *rsa.PublicKey
}

// ParseCOSEKey 解析 CBOR 编码的 COSE 公钥,仅支持 ES256(EC2/P-256)与 RS256。
func ParseCOSEKey(data []byte) (*PublicKey, error) {
	v, _, err := decodeCBOR(data)
	if err != nil {
		return nil, fmt.Errorf("解析公钥失败: %w", err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("公钥格式错误")
	}
	kty, _ := m[int64(1)].(int64)
	alg, _ := m[int64(3)].(int64)

	switch {
	case kty == 2 && alg == AlgES256: // EC2
		crv, _ := m[int64(-1)].(int64)
		if crv != 1 { // P-256
			return nil, errors.New("不支持的椭圆曲线")
		}
		xb, _ := m[int64(-2)].([]byte)
		yb, _ := m[int64(-3)].([]byte)
		if len(xb) != 32 || len(yb) != 32 {
			return nil, errors.New("公钥坐标长度错误")
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("公钥不在曲线上")
		}
		return &PublicKey{Alg: AlgES256, ec: pub}, nil

	case kty == 3 && alg == AlgRS256: // RSA
		nb, _ := m[int64(-1)].([]byte)
		eb, _ := m[int64(-2)].([]byte)
		if len(nb) < 256/2 || len(nb) > 1024 || len(eb) == 0 || len(eb) > 8 {
			return nil, errors.New("RSA 公钥参数错误")
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		if e < 3 {
			return nil, errors.New("RSA 公钥指数无效")
		}
		return &PublicKey{
			Alg: AlgRS256,
			rsa: &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e},
		}, nil
	}
	return nil, fmt.Errorf("不支持的公钥类型(kty=%d alg=%d),仅支持 ES256/RS256", kty, alg)
}

// Verify 校验签名,signed 为被签名的原始数据(内部做 SHA-256)。
func (k *PublicKey) Verify(signed, sig []byte) error {
	digest := sha256.Sum256(signed)
	switch {
	case k.ec != nil:
		if !ecdsa.VerifyASN1(k.ec, digest[:], sig) {
			return errors.New("签名校验失败")
		}
		return nil
	case k.rsa != nil:
		if err := rsa.VerifyPKCS1v15(k.rsa, crypto.SHA256, digest[:], sig); err != nil {
			return errors.New("签名校验失败")
		}
		return nil
	}
	return errors.New("公钥未初始化")
}

// ---------- clientData / authenticator data ----------

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// ClientDataChallenge 提取 clientDataJSON 中的挑战(base64url)。
func ClientDataChallenge(clientDataJSON []byte) (string, error) {
	var cd clientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return "", errors.New("clientData 解析失败")
	}
	if cd.Challenge == "" {
		return "", errors.New("clientData 缺少挑战")
	}
	return cd.Challenge, nil
}

func verifyClientData(clientDataJSON []byte, wantType, wantChallenge, rpID string) error {
	var cd clientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return errors.New("clientData 解析失败")
	}
	if cd.Type != wantType {
		return fmt.Errorf("clientData 类型错误: %s", cd.Type)
	}
	if cd.Challenge == "" || cd.Challenge != wantChallenge {
		return errors.New("挑战不匹配")
	}
	return checkOrigin(cd.Origin, rpID)
}

// checkOrigin 校验来源:主机必须与 rpID 一致,且为 HTTPS 或本机回环。
func checkOrigin(origin, rpID string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return fmt.Errorf("非法的来源: %s", origin)
	}
	host := u.Hostname()
	if !strings.EqualFold(host, rpID) {
		return fmt.Errorf("来源主机 %s 与 rpID %s 不匹配", host, rpID)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(host) {
		return nil
	}
	return errors.New("通行密钥要求 HTTPS 或 localhost 访问")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// authData 解析后的 authenticator data。
type authData struct {
	rpIDHash  []byte
	flags     byte
	signCount uint32
	credID    []byte
	coseKey   []byte
}

func parseAuthData(data []byte, needAttested bool) (*authData, error) {
	if len(data) < minAuthDataLen {
		return nil, errors.New("authenticator data 过短")
	}
	ad := &authData{
		rpIDHash:  data[:32],
		flags:     data[32],
		signCount: binary.BigEndian.Uint32(data[33:37]),
	}
	if !needAttested {
		return ad, nil
	}
	if ad.flags&flagAttestedCred == 0 {
		return nil, errors.New("缺少凭证数据")
	}
	rest := data[37:]
	if len(rest) < 18 { // aaguid(16) + credIdLen(2)
		return nil, errors.New("凭证数据过短")
	}
	idLen := int(binary.BigEndian.Uint16(rest[16:18]))
	if idLen == 0 || idLen > maxCredentialIDLen || len(rest) < 18+idLen {
		return nil, errors.New("凭证 ID 长度非法")
	}
	ad.credID = bytes.Clone(rest[18 : 18+idLen])
	coseRaw := rest[18+idLen:]
	if _, n, err := decodeCBOR(coseRaw); err != nil {
		return nil, fmt.Errorf("解析凭证公钥失败: %w", err)
	} else {
		ad.coseKey = bytes.Clone(coseRaw[:n])
	}
	return ad, nil
}

func verifyRPIDHash(got []byte, rpID string) error {
	want := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(got, want[:]) {
		return errors.New("rpID 哈希不匹配")
	}
	return nil
}

// ---------- 注册 ----------

// Credential 注册成功后得到的凭证。
type Credential struct {
	ID            []byte
	PublicKeyCOSE []byte
	Alg           int64
	SignCount     uint32
}

// FinishRegistration 校验注册响应并提取凭证。
// 采用 attestation=none 且注册要求已登录会话,故不校验证明语句(attStmt)。
func FinishRegistration(rpID, wantChallenge string, clientDataJSON, attestationObject []byte) (*Credential, error) {
	if err := verifyClientData(clientDataJSON, "webauthn.create", wantChallenge, rpID); err != nil {
		return nil, err
	}
	v, _, err := decodeCBOR(attestationObject)
	if err != nil {
		return nil, fmt.Errorf("attestationObject 解析失败: %w", err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("attestationObject 格式错误")
	}
	adBytes, ok := m["authData"].([]byte)
	if !ok {
		return nil, errors.New("attestationObject 缺少 authData")
	}
	ad, err := parseAuthData(adBytes, true)
	if err != nil {
		return nil, err
	}
	if err := verifyRPIDHash(ad.rpIDHash, rpID); err != nil {
		return nil, err
	}
	if ad.flags&flagUserPresent == 0 {
		return nil, errors.New("未通过用户在场校验")
	}
	key, err := ParseCOSEKey(ad.coseKey)
	if err != nil {
		return nil, err
	}
	return &Credential{
		ID:            ad.credID,
		PublicKeyCOSE: ad.coseKey,
		Alg:           key.Alg,
		SignCount:     ad.signCount,
	}, nil
}

// ---------- 登录 ----------

// FinishLogin 校验登录断言,成功返回新的签名计数。
func FinishLogin(rpID, wantChallenge string, coseKey, clientDataJSON, authenticatorData, signature []byte) (uint32, error) {
	if err := verifyClientData(clientDataJSON, "webauthn.get", wantChallenge, rpID); err != nil {
		return 0, err
	}
	ad, err := parseAuthData(authenticatorData, false)
	if err != nil {
		return 0, err
	}
	if err := verifyRPIDHash(ad.rpIDHash, rpID); err != nil {
		return 0, err
	}
	if ad.flags&flagUserPresent == 0 {
		return 0, errors.New("未通过用户在场校验")
	}
	key, err := ParseCOSEKey(coseKey)
	if err != nil {
		return 0, err
	}
	cdHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authenticatorData)+len(cdHash))
	signed = append(signed, authenticatorData...)
	signed = append(signed, cdHash[:]...)
	if err := key.Verify(signed, signature); err != nil {
		return 0, err
	}
	return ad.signCount, nil
}

// ---------- 浏览器选项构造 ----------

// CreationOptions 生成 navigator.credentials.create 的 publicKey 选项,
// 二进制字段以 base64url 编码,由前端解码。
func CreationOptions(rpID, rpName string, userID []byte, userName, challenge string, excludeIDs []string) map[string]any {
	exclude := make([]map[string]any, 0, len(excludeIDs))
	for _, id := range excludeIDs {
		exclude = append(exclude, map[string]any{"type": "public-key", "id": id})
	}
	return map[string]any{
		"challenge": challenge,
		"rp":        map[string]any{"id": rpID, "name": rpName},
		"user": map[string]any{
			"id":          b64.EncodeToString(userID),
			"name":        userName,
			"displayName": userName,
		},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": AlgES256},
			{"type": "public-key", "alg": AlgRS256},
		},
		"timeout":     60000,
		"attestation": "none",
		"authenticatorSelection": map[string]any{
			"residentKey":      "preferred",
			"userVerification": "preferred",
		},
		"excludeCredentials": exclude,
	}
}

// RequestOptions 生成 navigator.credentials.get 的 publicKey 选项。
func RequestOptions(rpID, challenge string, allowIDs []string) map[string]any {
	allow := make([]map[string]any, 0, len(allowIDs))
	for _, id := range allowIDs {
		allow = append(allow, map[string]any{"type": "public-key", "id": id})
	}
	return map[string]any{
		"challenge":        challenge,
		"rpId":             rpID,
		"timeout":          60000,
		"userVerification": "preferred",
		"allowCredentials": allow,
	}
}
