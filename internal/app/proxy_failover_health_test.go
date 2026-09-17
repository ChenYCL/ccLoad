package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestProxy_ProviderLocalFailuresFailoverToMatchingModel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "413_request_too_large",
			status: http.StatusRequestEntityTooLarge,
			body:   `{"code":"RequestTooLarge","message":"Request body size exceeds maximum allowed size"}`,
		},
		{
			name:   "400_empty_text",
			status: http.StatusBadRequest,
			body:   `{"type":"error","error":{"type":"invalid_request_error","message":"messages: text content blocks must be non-empty"}}`,
		},
		{
			name:   "403_permission",
			status: http.StatusForbidden,
			body:   `{"error":{"type":"permission_error","message":"request illegal"}}`,
		},
		{
			name:   "400_max_tokens",
			status: http.StatusBadRequest,
			body:   `{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: 324000 > 128000, which is the maximum allowed number of output tokens for claude-opus-5"}}`,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			modelName := "gpt-health-" + tt.name
			var primaryHits, backupHits atomic.Int64
			primary := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				primaryHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer primary.Close()
			backup := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				backupHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"chat-1","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
			}))
			defer backup.Close()

			env := setupProxyTestEnv(t, []testChannel{
				{name: "primary-" + tt.name, models: modelName, apiKey: "sk-1", priority: 100},
				{name: "backup-" + tt.name, models: modelName, apiKey: "sk-2", priority: 50},
			}, map[int]string{0: primary.URL, 1: backup.URL})

			body, _ := json.Marshal(map[string]any{
				"model":    modelName,
				"messages": []map[string]string{{"role": "user", "content": "hi"}},
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-api-key")
			w := httptest.NewRecorder()
			env.engine.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status=%d, want 200 after failover; body=%s", w.Code, w.Body.String())
			}
			if primaryHits.Load() == 0 {
				t.Fatal("primary channel was never tried")
			}
			if backupHits.Load() != 1 {
				t.Fatalf("backup hits=%d, want 1", backupHits.Load())
			}
		})
	}
}

func TestProxy_ContextLengthFailoversToMatchingModel(t *testing.T) {
	t.Parallel()
	var backupHits atomic.Int64
	primary := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","code":"context_length_exceeded","message":"Your input exceeds the context window of this model."}}`)
	}))
	defer primary.Close()
	backup := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backupHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chat-1","choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer backup.Close()

	env := setupProxyTestEnv(t, []testChannel{
		{name: "ctx-primary", models: "gpt-ctx-continue", apiKey: "sk-1", priority: 100},
		{name: "ctx-backup", models: "gpt-ctx-continue", apiKey: "sk-2", priority: 50},
	}, map[int]string{0: primary.URL, 1: backup.URL})

	body, _ := json.Marshal(map[string]any{
		"model":    "gpt-ctx-continue",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-api-key")
	w := httptest.NewRecorder()
	env.engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 after context-length failover; body=%s", w.Code, w.Body.String())
	}
	if backupHits.Load() != 1 {
		t.Fatalf("backup hits=%d, want 1", backupHits.Load())
	}
}
