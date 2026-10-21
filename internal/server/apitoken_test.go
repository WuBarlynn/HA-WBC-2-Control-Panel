package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"ha-wbc-console/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetupAdmin("secret1"); err != nil {
		t.Fatal(err)
	}
	webFS := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}}
	srv := New(st, webFS, nil)
	return srv, st
}

func doJSON(t *testing.T, srv *Server, method, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestAPITokenCreateListRevokeAndAuth(t *testing.T) {
	srv, st := newTestServer(t)

	// login as human
	code, out := doJSON(t, srv, "POST", "/api/login", "", map[string]string{"password": "secret1"})
	if code != 200 || out["ok"] != true {
		t.Fatalf("login: %d %v", code, out)
	}
	session := out["data"].(map[string]any)["token"].(string)

	// create token (default scopes)
	code, out = doJSON(t, srv, "POST", "/api/tokens", session, map[string]any{"name": "grok-bot"})
	if code != 200 {
		t.Fatalf("create: %d %v", code, out)
	}
	data := out["data"].(map[string]any)
	plain := data["token"].(string)
	if !strings.HasPrefix(plain, "wbc_") || len(plain) < 40 {
		t.Fatalf("bad token format: %q", plain)
	}
	rec := data["record"].(map[string]any)
	id := rec["id"].(string)
	scopes, _ := rec["scopes"].([]any)
	if len(scopes) != 2 {
		t.Fatalf("default scopes: %v", scopes)
	}

	// list must not contain plaintext or hash
	code, out = doJSON(t, srv, "GET", "/api/tokens", session, nil)
	if code != 200 {
		t.Fatalf("list: %d %v", code, out)
	}
	list := out["data"].([]any)
	if len(list) != 1 {
		t.Fatalf("list len %d", len(list))
	}
	item := list[0].(map[string]any)
	if _, ok := item["token"]; ok {
		t.Fatal("list leaked plaintext")
	}
	if _, ok := item["hash"]; ok {
		t.Fatal("list leaked hash")
	}
	if item["prefix"] == nil || item["prefix"] == "" {
		t.Fatal("missing prefix")
	}

	// API token can read overview
	code, out = doJSON(t, srv, "GET", "/api/overview", plain, nil)
	if code != 200 || out["ok"] != true {
		t.Fatalf("overview with api token: %d %v", code, out)
	}

	// API token cannot manage tokens
	code, out = doJSON(t, srv, "POST", "/api/tokens", plain, map[string]any{"name": "evil"})
	if code != 403 {
		t.Fatalf("token create with api token want 403 got %d %v", code, out)
	}

	// API token cannot factory-reset (session only)
	code, out = doJSON(t, srv, "POST", "/api/devices/x/factory-reset", plain, map[string]any{})
	if code != 403 {
		t.Fatalf("factory-reset want 403 got %d %v", code, out)
	}

	// revoke
	code, out = doJSON(t, srv, "DELETE", "/api/tokens/"+id, session, nil)
	if code != 200 {
		t.Fatalf("revoke: %d %v", code, out)
	}
	code, out = doJSON(t, srv, "GET", "/api/overview", plain, nil)
	if code != 401 {
		t.Fatalf("after revoke want 401 got %d %v", code, out)
	}

	// persistence: reopen store, token gone
	if n := len(st.APITokens()); n != 0 {
		t.Fatalf("store still has %d tokens", n)
	}
}

func TestAPITokenScopeReadOnly(t *testing.T) {
	srv, _ := newTestServer(t)
	_, out := doJSON(t, srv, "POST", "/api/login", "", map[string]string{"password": "secret1"})
	session := out["data"].(map[string]any)["token"].(string)

	code, out := doJSON(t, srv, "POST", "/api/tokens", session, map[string]any{
		"name":   "readonly",
		"scopes": []string{"read"},
	})
	if code != 200 {
		t.Fatalf("create: %d %v", code, out)
	}
	plain := out["data"].(map[string]any)["token"].(string)

	code, out = doJSON(t, srv, "GET", "/api/overview", plain, nil)
	if code != 200 {
		t.Fatalf("read overview: %d %v", code, out)
	}
	code, out = doJSON(t, srv, "POST", "/api/devices/x/power", plain, map[string]any{"state": true})
	if code != 403 {
		t.Fatalf("power without scope want 403 got %d %v", code, out)
	}
}

func TestAPITokenSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetupAdmin("secret1"); err != nil {
		t.Fatal(err)
	}
	rec, plain, err := st.CreateAPIToken("bot", []string{"read", "power"})
	if err != nil {
		t.Fatal(err)
	}
	st2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	found, ok := st2.FindAPITokenByPlain(plain)
	if !ok || found.ID != rec.ID {
		t.Fatalf("reload miss: ok=%v found=%+v", ok, found)
	}
}
