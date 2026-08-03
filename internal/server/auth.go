package server

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const sessionTTL = 24 * time.Hour

// sessions 内存态会话管理。
type sessions struct {
	mu sync.Mutex
	m  map[string]time.Time // token -> 过期时间
}

func newSessions() *sessions {
	return &sessions{m: make(map[string]time.Time)}
}

// create 生成新会话令牌。
func (s *sessions) create() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	s.m[tok] = time.Now().Add(sessionTTL)
	return tok
}

// valid 校验令牌并滑动续期。
func (s *sessions) valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, tok)
		return false
	}
	s.m[tok] = time.Now().Add(sessionTTL)
	return true
}

// revoke 注销令牌。
func (s *sessions) revoke(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tok)
}

// gcLocked 清理过期会话,调用方需持锁。
func (s *sessions) gcLocked() {
	now := time.Now()
	for k, exp := range s.m {
		if now.After(exp) {
			delete(s.m, k)
		}
	}
}
