package app

import (
	"net/http"
	"testing"
	"time"

	"ccLoad/internal/protocol"
)

func TestUnsupportedProtocolBackoffDoublesUntilCap(t *testing.T) {
	t.Parallel()
	if got := unsupportedProtocolBackoff(1); got != time.Minute {
		t.Fatalf("failures=1 delay=%s, want 1m", got)
	}
	if got := unsupportedProtocolBackoff(2); got != 2*time.Minute {
		t.Fatalf("failures=2 delay=%s, want 2m", got)
	}
	if got := unsupportedProtocolBackoff(3); got != 4*time.Minute {
		t.Fatalf("failures=3 delay=%s, want 4m", got)
	}
	if got := unsupportedProtocolBackoff(4); got != 8*time.Minute {
		t.Fatalf("failures=4 delay=%s, want 8m", got)
	}
	if got := unsupportedProtocolBackoff(5); got != unsupportedProtocolCapabilityTTL {
		t.Fatalf("failures=5 delay=%s, want cap %s", got, unsupportedProtocolCapabilityTTL)
	}
	if got := unsupportedProtocolBackoff(9); got != unsupportedProtocolCapabilityTTL {
		t.Fatalf("failures=9 delay=%s, want cap", got)
	}
}

func TestProtocolCapabilityUnsupportedBackoffKeepsFailureCount(t *testing.T) {
	t.Parallel()
	cache := &protocolCapabilityCache{}
	key := protocolCapabilityKey{
		channelID: 7, baseURL: "https://cli-chat-proxy.grok.com/v1",
		clientProtocol: protocol.Codex, requestFamily: protocol.RequestFamilyResponses,
	}
	cache.set(key, protocolUnsupported)
	first := cache.entries[key]
	if first.failures != 1 {
		t.Fatalf("failures=%d, want 1", first.failures)
	}
	delay1 := time.Until(first.retryAfter)
	if delay1 < 50*time.Second || delay1 > 70*time.Second {
		t.Fatalf("first retryAfter delay=%s, want ~1m", delay1)
	}
	if _, known := cache.get(key); !known {
		t.Fatal("fresh unsupported sentinel should be known")
	}

	cache.set(key, protocolUnsupported)
	second := cache.entries[key]
	if second.failures != 2 {
		t.Fatalf("failures=%d, want 2", second.failures)
	}
	delay2 := time.Until(second.retryAfter)
	if delay2 < 110*time.Second || delay2 > 130*time.Second {
		t.Fatalf("second retryAfter delay=%s, want ~2m", delay2)
	}

	cache.set(key, protocol.Anthropic)
	if got, known := cache.get(key); !known || got != protocol.Anthropic {
		t.Fatalf("get after success = (%q,%v), want anthropic", got, known)
	}
	if cache.entries[key].failures != 0 {
		t.Fatalf("success should reset failures, got %d", cache.entries[key].failures)
	}
}

func TestProtocolCapabilitySessionIsolation(t *testing.T) {
	t.Parallel()
	cache := &protocolCapabilityCache{}
	base := protocolCapabilityKey{
		channelID: 21, baseURL: "https://cli-chat-proxy.grok.com/v1",
		clientProtocol: protocol.Codex, requestFamily: protocol.RequestFamilyResponses,
	}
	sessionA := base
	sessionA.sessionID = "sess-a"
	sessionB := base
	sessionB.sessionID = "sess-b"
	cache.set(sessionA, protocol.Anthropic)
	cache.set(sessionB, protocolUnsupported)
	if got, known := cache.get(sessionA); !known || got != protocol.Anthropic {
		t.Fatalf("session A get = (%q,%v), want anthropic", got, known)
	}
	if got, known := cache.get(sessionB); !known || got != protocolUnsupported {
		t.Fatalf("session B get = (%q,%v), want unsupported", got, known)
	}
	anon := base
	if _, known := cache.get(anon); known {
		t.Fatal("empty session must not inherit another session's probe")
	}
}

func TestProtocolCapabilitySessionIDFromHeaders(t *testing.T) {
	t.Parallel()
	h := make(http.Header)
	h.Set("Session-Id", "codex-sess")
	h.Set("Thread-Id", "thread-1")
	got := protocolCapabilitySessionID(&proxyRequestContext{header: h})
	if got != "codex-sess\x00thread\x00thread-1" {
		t.Fatalf("session id = %q", got)
	}
	h2 := make(http.Header)
	h2.Set("X-Claude-Code-Session-Id", "claude-sess")
	got = protocolCapabilitySessionID(&proxyRequestContext{header: h2})
	if got != "claude-sess" {
		t.Fatalf("claude session id = %q", got)
	}
	h3 := make(http.Header)
	h3.Set("x-opencode-session", "oc-sess")
	h3.Set("x-client-request-id", "req-1")
	got = protocolCapabilitySessionID(&proxyRequestContext{header: h3})
	if got != "oc-sess" {
		t.Fatalf("opencode session id = %q", got)
	}
	h4 := make(http.Header)
	h4.Set("x-client-request-id", "req-only")
	if got = protocolCapabilitySessionID(&proxyRequestContext{header: h4}); got != "" {
		t.Fatalf("request id must not scope capability, got %q", got)
	}
	if got = protocolCapabilitySessionID(&proxyRequestContext{}); got != "" {
		t.Fatalf("empty ctx session id = %q", got)
	}
	store := &responsesExecutionSession{storeKey: "exec-store"}
	got = protocolCapabilitySessionID(&proxyRequestContext{routingSession: store})
	if got != "exec-store" {
		t.Fatalf("routing session id = %q", got)
	}
	got = protocolCapabilitySessionID(&proxyRequestContext{tokenHash: "abc123"})
	if got != "tok:abc123" {
		t.Fatalf("token fallback session id = %q", got)
	}
	h5 := make(http.Header)
	h5.Set("Session-Id", "real-sess")
	got = protocolCapabilitySessionID(&proxyRequestContext{header: h5, tokenHash: "abc123"})
	if got != "real-sess" {
		t.Fatalf("explicit session must win over token, got %q", got)
	}
	body := []byte(`{"metadata":{"user_id":"{\"session_id\":\"body-sess\"}"},"messages":[]}`)
	got = protocolCapabilitySessionID(&proxyRequestContext{body: body, tokenHash: "abc123"})
	if got != "body-sess" {
		t.Fatalf("anthropic body session id = %q", got)
	}
}

func TestProtocolCapabilityExpiredUnsupportedAllowsReprobe(t *testing.T) {
	t.Parallel()
	cache := &protocolCapabilityCache{entries: map[protocolCapabilityKey]protocolCapabilityEntry{}}
	key := protocolCapabilityKey{
		channelID: 8, baseURL: "https://example.com/v1",
		clientProtocol: protocol.OpenAI, requestFamily: protocol.RequestFamilyChatCompletions,
	}
	now := time.Now()
	cache.entries[key] = protocolCapabilityEntry{
		upstream:   protocolUnsupported,
		retryAfter: now.Add(-time.Second),
		expireAt:   now.Add(protocolCapabilitySessionTTL),
		failures:   3,
	}
	if _, known := cache.get(key); known {
		t.Fatal("expired unsupported should re-probe")
	}
	if cache.entries[key].failures != 3 {
		t.Fatal("re-probe must keep failure count for the next set()")
	}
}

func TestProtocolCapabilityIdleExpireReleasesAndRelearns(t *testing.T) {
	t.Parallel()
	cache := &protocolCapabilityCache{}
	key := protocolCapabilityKey{
		channelID: 21, baseURL: "https://cli-chat-proxy.grok.com/v1",
		clientProtocol: protocol.Codex, requestFamily: protocol.RequestFamilyResponses,
		sessionID: "sess-idle",
	}
	cache.set(key, protocol.Anthropic)
	entry := cache.entries[key]
	entry.expireAt = time.Now().Add(-time.Second)
	cache.entries[key] = entry
	if _, known := cache.get(key); known {
		t.Fatal("idle session must be released")
	}
	if _, ok := cache.entries[key]; ok {
		t.Fatal("idle session entry must be deleted")
	}
	cache.set(key, protocol.Anthropic)
	if got, known := cache.get(key); !known || got != protocol.Anthropic {
		t.Fatalf("reconnect re-learn = (%q,%v), want anthropic", got, known)
	}
}

func TestProtocolCapabilityIdleExpireResetsUnsupportedBackoff(t *testing.T) {
	t.Parallel()
	cache := &protocolCapabilityCache{}
	key := protocolCapabilityKey{
		channelID: 21, baseURL: "https://cli-chat-proxy.grok.com/v1",
		clientProtocol: protocol.Codex, requestFamily: protocol.RequestFamilyResponses,
		sessionID: "sess-idle-unsup",
	}
	cache.set(key, protocolUnsupported)
	cache.set(key, protocolUnsupported)
	if cache.entries[key].failures != 2 {
		t.Fatalf("failures=%d, want 2", cache.entries[key].failures)
	}
	entry := cache.entries[key]
	entry.expireAt = time.Now().Add(-time.Second)
	cache.entries[key] = entry
	if removed := cache.evictExpired(time.Now()); removed != 1 {
		t.Fatalf("evictExpired removed=%d, want 1", removed)
	}
	if _, ok := cache.entries[key]; ok {
		t.Fatal("idle unsupported entry must be deleted")
	}
	cache.set(key, protocolUnsupported)
	if cache.entries[key].failures != 1 {
		t.Fatalf("reconnect backoff failures=%d, want 1", cache.entries[key].failures)
	}
}

func TestProtocolCapabilityGetTouchesIdleDeadline(t *testing.T) {
	t.Parallel()
	cache := &protocolCapabilityCache{}
	key := protocolCapabilityKey{
		channelID: 11, baseURL: "https://cli-chat-proxy.grok.com/v1",
		clientProtocol: protocol.Codex, requestFamily: protocol.RequestFamilyResponses,
		sessionID: "sess-touch",
	}
	cache.set(key, protocol.Anthropic)
	entry := cache.entries[key]
	entry.expireAt = time.Now().Add(time.Minute)
	cache.entries[key] = entry
	if _, known := cache.get(key); !known {
		t.Fatal("active session should still be known")
	}
	remaining := time.Until(cache.entries[key].expireAt)
	if remaining < 14*time.Minute {
		t.Fatalf("touched deadline remaining=%s, want ~15m", remaining)
	}
}
