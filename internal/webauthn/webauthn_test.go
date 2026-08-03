package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// ---- 测试用最小 CBOR 编码器(模拟认证器输出) ----

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	}
}

func cborInt(v int64) []byte {
	if v >= 0 {
		return cborHead(0, uint64(v))
	}
	return cborHead(1, uint64(-1-v))
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

func coseES256(pub *ecdsa.PublicKey) []byte {
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))
	var out []byte
	out = append(out, cborHead(5, 5)...)
	out = append(out, cborInt(1)...)
	out = append(out, cborInt(2)...)
	out = append(out, cborInt(3)...)
	out = append(out, cborInt(-7)...)
	out = append(out, cborInt(-1)...)
	out = append(out, cborInt(1)...)
	out = append(out, cborInt(-2)...)
	out = append(out, cborBytes(x)...)
	out = append(out, cborInt(-3)...)
	out = append(out, cborBytes(y)...)
	return out
}

func coseRS256(pub *rsa.PublicKey) []byte {
	e := []byte{0x01, 0x00, 0x01}
	var out []byte
	out = append(out, cborHead(5, 4)...)
	out = append(out, cborInt(1)...)
	out = append(out, cborInt(3)...)
	out = append(out, cborInt(3)...)
	out = append(out, cborInt(-257)...)
	out = append(out, cborInt(-1)...)
	out = append(out, cborBytes(pub.N.Bytes())...)
	out = append(out, cborInt(-2)...)
	out = append(out, cborBytes(e)...)
	return out
}

func buildAuthData(rpID string, flags byte, count uint32, credID, coseKey []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], count)
	out = append(out, cnt[:]...)
	if flags&flagAttestedCred != 0 {
		out = append(out, make([]byte, 16)...) // aaguid
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(credID)))
		out = append(out, l[:]...)
		out = append(out, credID...)
		out = append(out, coseKey...)
	}
	return out
}

func buildAttestationObject(authData []byte) []byte {
	var out []byte
	out = append(out, cborHead(5, 3)...)
	out = append(out, cborText("fmt")...)
	out = append(out, cborText("none")...)
	out = append(out, cborText("attStmt")...)
	out = append(out, cborHead(5, 0)...)
	out = append(out, cborText("authData")...)
	out = append(out, cborBytes(authData)...)
	return out
}

func clientDataJSON(t, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]string{"type": t, "challenge": challenge, "origin": origin})
	return b
}

// simAuthenticator 模拟认证器。
type simAuthenticator struct {
	priv   *ecdsa.PrivateKey
	credID []byte
}

func newSim(t *testing.T) *simAuthenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	return &simAuthenticator{priv: priv, credID: credID}
}

func (a *simAuthenticator) register(rpID, challenge, origin string) (cdj, att []byte) {
	authData := buildAuthData(rpID, flagUserPresent|flagAttestedCred, 0, a.credID, coseES256(&a.priv.PublicKey))
	return clientDataJSON("webauthn.create", challenge, origin), buildAttestationObject(authData)
}

func (a *simAuthenticator) assert(t *testing.T, rpID, challenge, origin string, count uint32) (cdj, authData, sig []byte) {
	t.Helper()
	cdj = clientDataJSON("webauthn.get", challenge, origin)
	authData = buildAuthData(rpID, flagUserPresent, count, nil, nil)
	cdHash := sha256.Sum256(cdj)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	s, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return cdj, authData, s
}

// ---- 测试 ----

const (
	rpID   = "wbc.example.com"
	origin = "https://wbc.example.com:8443"
)

func TestRegisterAndLogin(t *testing.T) {
	sim := newSim(t)
	ch := NewChallenges()

	regCh := ch.New("register")
	cdj, att := sim.register(rpID, regCh, origin)
	if !ch.Consume("register", regCh) {
		t.Fatal("挑战应可消费")
	}
	cred, err := FinishRegistration(rpID, regCh, cdj, att)
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	if string(cred.ID) != string(sim.credID) {
		t.Fatal("凭证 ID 不匹配")
	}
	if cred.Alg != AlgES256 {
		t.Fatalf("算法错误: %d", cred.Alg)
	}

	loginCh := ch.New("login")
	lcdj, authData, sig := sim.assert(t, rpID, loginCh, origin, 7)
	count, err := FinishLogin(rpID, loginCh, cred.PublicKeyCOSE, lcdj, authData, sig)
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if count != 7 {
		t.Fatalf("签名计数错误: %d", count)
	}
}

func TestLoginFailures(t *testing.T) {
	sim := newSim(t)
	cdj, att := sim.register(rpID, "chal-1", origin)
	cred, err := FinishRegistration(rpID, "chal-1", cdj, att)
	if err != nil {
		t.Fatal(err)
	}

	// 错误挑战
	lcdj, authData, sig := sim.assert(t, rpID, "chal-A", origin, 1)
	if _, err := FinishLogin(rpID, "chal-B", cred.PublicKeyCOSE, lcdj, authData, sig); err == nil {
		t.Fatal("错误挑战应失败")
	}
	// 错误来源:主机不匹配
	lcdj, authData, sig = sim.assert(t, rpID, "chal-2", "https://evil.example.com", 1)
	if _, err := FinishLogin(rpID, "chal-2", cred.PublicKeyCOSE, lcdj, authData, sig); err == nil {
		t.Fatal("来源不匹配应失败")
	}
	// 非 HTTPS 且非 localhost
	lcdj, authData, sig = sim.assert(t, rpID, "chal-3", "http://wbc.example.com", 1)
	if _, err := FinishLogin(rpID, "chal-3", cred.PublicKeyCOSE, lcdj, authData, sig); err == nil {
		t.Fatal("非安全上下文应失败")
	}
	// 篡改签名
	lcdj, authData, sig = sim.assert(t, rpID, "chal-4", origin, 1)
	sig[len(sig)-1] ^= 0xff
	if _, err := FinishLogin(rpID, "chal-4", cred.PublicKeyCOSE, lcdj, authData, sig); err == nil {
		t.Fatal("篡改签名应失败")
	}
	// rpID 哈希不匹配
	other := newSim(t)
	lcdj2 := clientDataJSON("webauthn.get", "chal-5", origin)
	badAuth := buildAuthData("other.example.com", flagUserPresent, 1, nil, nil)
	cdHash := sha256.Sum256(lcdj2)
	digest := sha256.Sum256(append(append([]byte{}, badAuth...), cdHash[:]...))
	s2, _ := ecdsa.SignASN1(rand.Reader, other.priv, digest[:])
	if _, err := FinishLogin(rpID, "chal-5", cred.PublicKeyCOSE, lcdj2, badAuth, s2); err == nil {
		t.Fatal("rpID 哈希不匹配应失败")
	}
	// 用户不在场
	lcdj, authData, sig = sim.assert(t, rpID, "chal-6", origin, 1)
	authData[32] &^= flagUserPresent
	cdHash6 := sha256.Sum256(lcdj)
	digest6 := sha256.Sum256(append(append([]byte{}, authData...), cdHash6[:]...))
	sig, _ = ecdsa.SignASN1(rand.Reader, sim.priv, digest6[:])
	if _, err := FinishLogin(rpID, "chal-6", cred.PublicKeyCOSE, lcdj, authData, sig); err == nil {
		t.Fatal("用户不在场应失败")
	}
}

func TestRegistrationFailures(t *testing.T) {
	sim := newSim(t)
	// clientData 类型错误
	cdj := clientDataJSON("webauthn.get", "c1", origin)
	_, att := sim.register(rpID, "c1", origin)
	if _, err := FinishRegistration(rpID, "c1", cdj, att); err == nil {
		t.Fatal("类型错误应失败")
	}
	// rpID 不一致
	cdj2, att2 := sim.register("other.example.com", "c2", origin)
	if _, err := FinishRegistration(rpID, "c2", cdj2, att2); err == nil {
		t.Fatal("rpID 哈希不匹配应失败")
	}
	// attestationObject 损坏
	cdj3, att3 := sim.register(rpID, "c3", origin)
	att3 = att3[:len(att3)/2]
	if _, err := FinishRegistration(rpID, "c3", cdj3, att3); err == nil {
		t.Fatal("损坏的 attestationObject 应失败")
	}
}

func TestLocalhostHTTP(t *testing.T) {
	sim := newSim(t)
	cdj, att := sim.register("localhost", "c1", "http://localhost:8088")
	cred, err := FinishRegistration("localhost", "c1", cdj, att)
	if err != nil {
		t.Fatalf("localhost http 注册应成功: %v", err)
	}
	lcdj, authData, sig := sim.assert(t, "localhost", "c2", "http://localhost:8088", 2)
	if _, err := FinishLogin("localhost", "c2", cred.PublicKeyCOSE, lcdj, authData, sig); err != nil {
		t.Fatalf("localhost http 登录应成功: %v", err)
	}
}

func TestChallengeOneTime(t *testing.T) {
	ch := NewChallenges()
	c := ch.New("login")
	if !ch.Consume("login", c) {
		t.Fatal("首次消费应成功")
	}
	if ch.Consume("login", c) {
		t.Fatal("重复消费应失败")
	}
	c2 := ch.New("register")
	if ch.Consume("login", c2) {
		t.Fatal("用途不符应失败")
	}
	if ch.Consume("login", "不存在的挑战") {
		t.Fatal("未知挑战应失败")
	}
}

func TestRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cose := coseRS256(&priv.PublicKey)
	pk, err := ParseCOSEKey(cose)
	if err != nil {
		t.Fatalf("RS256 公钥解析失败: %v", err)
	}
	if pk.Alg != AlgRS256 {
		t.Fatalf("算法错误: %d", pk.Alg)
	}
	msg := []byte("test-message")
	digest := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := pk.Verify(msg, sig); err != nil {
		t.Fatalf("RS256 验签失败: %v", err)
	}
	sig[0] ^= 0xff
	if err := pk.Verify(msg, sig); err == nil {
		t.Fatal("篡改签名应失败")
	}
}
