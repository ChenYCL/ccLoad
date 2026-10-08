package app

import (
	"net/http"
	"testing"

	"ccLoad/internal/githubcopilotauth"
	"ccLoad/internal/model"
	"ccLoad/internal/protocol"
)

func TestInjectGitHubCopilotHeadersMessagesProxy(t *testing.T) {
	t.Parallel()
	req, err := http.NewRequest(http.MethodPost, githubcopilotauth.APIBaseURL+"/v1/messages", nil)
	if err != nil {
		t.Fatal(err)
	}
	incoming := http.Header{}
	incoming.Set("X-Claude-Code-Session-Id", "sess-abc")
	incoming.Set("Anthropic-Beta", "claude-code-20250219")
	cfg := &model.Config{AuthType: model.AuthTypeGitHubCopilotOAuth}
	injectGitHubCopilotHeaders(req, cfg, "copilot-token", incoming, protocol.Anthropic)
	if got := req.Header.Get("Openai-Intent"); got != "messages-proxy" {
		t.Fatalf("intent=%q", got)
	}
	if got := req.Header.Get("X-Interaction-Id"); got != "sess-abc" {
		t.Fatalf("session=%q", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer copilot-token" {
		t.Fatalf("auth=%q", got)
	}
	if got := req.Header.Get("Anthropic-Beta"); got != "claude-code-20250219" {
		t.Fatalf("beta=%q", got)
	}
}
