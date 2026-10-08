package githubcopilotauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseCredential(t *testing.T) {
	t.Parallel()
	raw := `{"type":"github_copilot","github_token":"gho_abc","copilot_token":"tid=1","login":"octo"}`
	c, err := ParseCredential([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint() != APIBaseURL || c.Login != "octo" {
		t.Fatalf("%+v", c)
	}
	if !c.NeedsRefresh(time.Now()) {
		t.Fatal("missing expiry must refresh")
	}
}

func TestDeviceFlowAndCompleteLogin(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/login/device/code", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dev", "user_code": "ABCD-1234",
			"verification_uri":          "https://github.com/login/device",
			"verification_uri_complete": "https://github.com/login/device?user_code=ABCD-1234",
			"expires_in":                900, "interval": 1,
		})
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "device_code=dev") {
			t.Fatalf("body=%s", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_login"})
	})
	mux.HandleFunc("/copilot_internal/v2/token", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "token gho_login" {
			t.Fatalf("auth=%q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "copilot-key", "expires_at": time.Now().Add(time.Hour).Unix(),
			"sku":       "copilot_for_business_seat",
			"endpoints": map[string]string{"api": "https://api.githubcopilot.com"},
		})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"login": "octocat", "name": "Octo"})
	})
	mux.HandleFunc("/models", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer copilot-key" {
			t.Fatalf("models auth=%q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "claude-sonnet-4.5", "policy": map[string]string{"state": "enabled"}},
				{"id": "gpt-4o", "policy": map[string]string{"state": "disabled"}},
			},
		})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	service := NewService(server.Client())
	service.DeviceCodeURL = server.URL + "/login/device/code"
	service.AccessTokenURL = server.URL + "/login/oauth/access_token"
	service.CopilotTokenURL = server.URL + "/copilot_internal/v2/token"
	service.UserURL = server.URL + "/user"
	ctx := context.Background()
	flow, err := service.StartDeviceFlow(ctx)
	if err != nil || flow.UserCode != "ABCD-1234" {
		t.Fatalf("flow=%+v err=%v", flow, err)
	}
	token, err := service.PollAccessToken(ctx, flow.DeviceCode)
	if err != nil || token != "gho_login" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	cred, err := service.CompleteLogin(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Login != "octocat" || cred.CopilotToken != "copilot-key" || cred.SKU != "copilot_for_business_seat" {
		t.Fatalf("%+v", cred)
	}
	models, err := service.FetchModels(ctx, cred.CopilotToken, server.URL)
	if err != nil || len(models) != 1 || models[0] != "claude-sonnet-4.5" {
		t.Fatalf("models=%v err=%v", models, err)
	}
}

func TestAnthropicMessagesHeaders(t *testing.T) {
	t.Parallel()
	h := AnthropicMessagesHeaders("tok", "sess-1", "req-1")
	if h.Get("Openai-Intent") != "messages-proxy" {
		t.Fatalf("%v", h)
	}
	if h.Get("X-Interaction-Id") != "sess-1" || h.Get("Authorization") != "Bearer tok" {
		t.Fatalf("%v", h)
	}
}
