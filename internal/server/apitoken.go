package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"ha-wbc-console/internal/store"
)

type authKind string

const (
	authKindSession  authKind = "session"
	authKindAPIToken authKind = "api_token"
)

type authInfo struct {
	Kind    authKind
	TokenID string
	Name    string
	Scopes  []string // session: nil = full access
}

type ctxKey int

const authCtxKey ctxKey = 1

func withAuth(ctx context.Context, info authInfo) context.Context {
	return context.WithValue(ctx, authCtxKey, info)
}

// publicAPIToken 返回给前端的 API Token 信息(无明文、无哈希)。
type publicAPIToken struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Prefix     string    `json:"prefix"`
	Scopes     []string  `json:"scopes"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt,omitempty"`
}

func toPublicAPIToken(t store.APIToken) publicAPIToken {
	return publicAPIToken{
		ID:         t.ID,
		Name:       t.Name,
		Prefix:     t.Prefix,
		Scopes:     append([]string(nil), t.Scopes...),
		CreatedAt:  t.CreatedAt,
		LastUsedAt: t.LastUsedAt,
	}
}

// resolveAuth 解析 Bearer:先认内存会话,再认持久化 API Token。
func (s *Server) resolveAuth(r *http.Request) (authInfo, bool) {
	tok := bearerToken(r)
	if tok == "" {
		return authInfo{}, false
	}
	if s.sessions.valid(tok) {
		return authInfo{Kind: authKindSession}, true
	}
	rec, ok := s.store.FindAPITokenByPlain(tok)
	if !ok {
		return authInfo{}, false
	}
	return authInfo{
		Kind:    authKindAPIToken,
		TokenID: rec.ID,
		Name:    rec.Name,
		Scopes:  append([]string(nil), rec.Scopes...),
	}, true
}

func touchIfAPIToken(s *Server, info authInfo) {
	if info.Kind == authKindAPIToken && info.TokenID != "" {
		s.store.TouchAPITokenUsage(info.TokenID)
	}
}

// authed 接受人类会话或任意有效 API Token(后续由 requireScope 收紧)。
func (s *Server) authed(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := s.resolveAuth(r)
		if !ok {
			fail(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		touchIfAPIToken(s, info)
		next(w, r.WithContext(withAuth(r.Context(), info)))
	})
}

// sessionOnly 仅人类会话可用;拒绝 API Token(改密、Passkey、Token 管理等)。
func (s *Server) sessionOnly(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := s.resolveAuth(r)
		if !ok {
			fail(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		if info.Kind != authKindSession {
			fail(w, http.StatusForbidden, "此接口仅允许人类会话,请用密码或通行密钥登录后操作")
			return
		}
		next(w, r.WithContext(withAuth(r.Context(), info)))
	})
}

// requireScope 人类会话全放行;API Token 必须具备指定 scope。
func (s *Server) requireScope(scope string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := s.resolveAuth(r)
		if !ok {
			fail(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		if info.Kind == authKindAPIToken && !store.HasScope(info.Scopes, scope) {
			fail(w, http.StatusForbidden, "API Token 缺少权限: "+scope)
			return
		}
		touchIfAPIToken(s, info)
		next(w, r.WithContext(withAuth(r.Context(), info)))
	})
}

// handleListAPITokens 列出全部 API Token(无明文)。
func (s *Server) handleListAPITokens(w http.ResponseWriter, r *http.Request) {
	list := s.store.APITokens()
	out := make([]publicAPIToken, 0, len(list))
	for _, t := range list {
		out = append(out, toPublicAPIToken(t))
	}
	ok(w, out)
}

// handleCreateAPIToken 创建 Token,明文仅此响应返回一次。
func (s *Server) handleCreateAPIToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := readBody(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	rec, plain, err := s.store.CreateAPIToken(body.Name, body.Scopes)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("API Token 已创建 id=%s name=%q scopes=%v", rec.ID, rec.Name, rec.Scopes)
	ok(w, map[string]any{
		"token":  plain,
		"record": toPublicAPIToken(rec),
	})
}

// handleDeleteAPIToken 吊销 Token。
func (s *Server) handleDeleteAPIToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteAPIToken(id); err != nil {
		if errors.Is(err, store.ErrAPITokenNotFound) {
			fail(w, http.StatusNotFound, err.Error())
			return
		}
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("API Token 已吊销 id=%s", id)
	ok(w, nil)
}
