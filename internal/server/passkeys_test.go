package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"testing/fstest"

	"ha-wbc-console/internal/store"
)

// ---- 模拟认证器(与 webauthn 包测试相同的最小 CBOR 编码) ----

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
	out := cborHead(5, 5)
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

func buildAuthData(rpID string, flags byte, count uint32, credID, coseKey []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], count)
	out = append(out, cnt[:]...)
	if flags&0x40 != 0 {
		out = append(out, make([]byte, 16)...)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(credID)))
		out = append(out, l[:]...)
		out = append(out, credID...)
		out = append(out, coseKey...)
	}
	return out
}

func buildAttestationObject(authData []byte) []byte {
	out := cborHead(5, 3)
	out = append(out, cborText("fmt")...)
	out = append(out, cborText("none")...)
	out = append(out, cborText("attStmt")...)
	out = append(out, cborHead(5, 0)...)
	out = append(out, cborText("authData")...)
	out = append(out, cborBytes(authData)...)
	return out
}

// ---- 测试辅助 ----

type testEnv struct {
	t   *testing.T
	srv *httptest.Server
}

// call 以 wbc.test 作为 Host 发起 JSON 请求。
func (e *testEnv) call(method, path, token string, body any) (int, map[string]any) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, &buf)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Host = "wbc.test"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func data(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	d, ok := m["data"].(map[string]any)
	if !ok {
		t.Fatalf("响应缺少 data: %v", m)
	}
	return d
}

func TestPasskeyFullFlow(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	webFS := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}}
	env := &testEnv{t: t, srv: httptest.NewServer(New(st, webFS))}
	defer env.srv.Close()

	// 初始化并登录
	code, m := env.call("POST", "/api/setup", "", map[string]any{"password": "admin123"})
	if code != 200 {
		t.Fatalf("setup 失败: %v", m)
	}
	token := data(t, m)["token"].(string)

	// 生成模拟认证器
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := make([]byte, 32)
	_, _ = rand.Read(credID)
	b64 := base64.RawURLEncoding
	const rpID = "wbc.test"
	const origin = "https://wbc.test"

	// 注册 begin
	code, m = env.call("POST", "/api/passkey/register/begin", token, nil)
	if code != 200 {
		t.Fatalf("register/begin 失败: %v", m)
	}
	pk := data(t, m)["publicKey"].(map[string]any)
	challenge := pk["challenge"].(string)
	if pk["rp"].(map[string]any)["id"] != rpID {
		t.Fatalf("rpID 错误: %v", pk["rp"])
	}

	// 注册 finish
	cdj, _ := json.Marshal(map[string]string{"type": "webauthn.create", "challenge": challenge, "origin": origin})
	authData := buildAuthData(rpID, 0x41, 0, credID, coseES256(&priv.PublicKey))
	code, m = env.call("POST", "/api/passkey/register/finish", token, map[string]any{
		"name":              "测试密钥",
		"clientDataJSON":    b64.EncodeToString(cdj),
		"attestationObject": b64.EncodeToString(buildAttestationObject(authData)),
	})
	if code != 200 {
		t.Fatalf("register/finish 失败: %v", m)
	}

	// state 应报告 1 个通行密钥
	code, m = env.call("GET", "/api/state", "", nil)
	if code != 200 || data(t, m)["passkeys"].(float64) != 1 {
		t.Fatalf("state 未反映通行密钥: %v", m)
	}

	// 登录 begin
	code, m = env.call("POST", "/api/passkey/login/begin", "", nil)
	if code != 200 {
		t.Fatalf("login/begin 失败: %v", m)
	}
	lpk := data(t, m)["publicKey"].(map[string]any)
	loginCh := lpk["challenge"].(string)
	allow := lpk["allowCredentials"].([]any)
	if len(allow) != 1 || allow[0].(map[string]any)["id"] != b64.EncodeToString(credID) {
		t.Fatalf("allowCredentials 错误: %v", allow)
	}

	// 登录 finish:构造断言
	lcdj, _ := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": loginCh, "origin": origin})
	lauth := buildAuthData(rpID, 0x01, 3, nil, nil)
	cdHash := sha256.Sum256(lcdj)
	digest := sha256.Sum256(append(append([]byte{}, lauth...), cdHash[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	code, m = env.call("POST", "/api/passkey/login/finish", "", map[string]any{
		"id":                b64.EncodeToString(credID),
		"clientDataJSON":    b64.EncodeToString(lcdj),
		"authenticatorData": b64.EncodeToString(lauth),
		"signature":         b64.EncodeToString(sig),
	})
	if code != 200 {
		t.Fatalf("login/finish 失败: %v", m)
	}
	newToken := data(t, m)["token"].(string)

	// 新令牌可用
	code, _ = env.call("GET", "/api/devices", newToken, nil)
	if code != 200 {
		t.Fatalf("通行密钥登录的令牌无法访问受保护接口: %d", code)
	}

	// 挑战不可重放:重放同一断言应失败
	code, m = env.call("POST", "/api/passkey/login/finish", "", map[string]any{
		"id":                b64.EncodeToString(credID),
		"clientDataJSON":    b64.EncodeToString(lcdj),
		"authenticatorData": b64.EncodeToString(lauth),
		"signature":         b64.EncodeToString(sig),
	})
	if code != 401 {
		t.Fatalf("重放断言应被拒绝: %d %v", code, m)
	}

	// 删除通行密钥
	code, m = env.call("DELETE", "/api/passkey/"+b64.EncodeToString(credID), newToken, nil)
	if code != 200 {
		t.Fatalf("删除失败: %v", m)
	}
	code, m = env.call("GET", "/api/state", "", nil)
	if data(t, m)["passkeys"].(float64) != 0 {
		t.Fatalf("删除后计数应为 0: %v", m)
	}
}
