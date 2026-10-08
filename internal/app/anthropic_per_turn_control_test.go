package app

import (
	"net/http"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestAnthropicClaudeCodeBetasIncludesPerTurnControlForMessageOutputConfig(t *testing.T) {
	t.Parallel()
	body := []byte(`{"model":"claude-opus-5-5","output_config":{"effort":"xhigh"},"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"ok"},{"role":"user","content":"next"},{"role":"system","content":"turn control","output_config":{"effort":"xhigh"}}]}`)
	betas := anthropicClaudeCodeBetas(body, true)
	for _, want := range []string{
		"per-turn-control-2026-07-01",
		"thinking-binding-controls-2026-08-01",
		"mid-conversation-system-clear-at-2026-08-21",
		"extended-cache-ttl-2025-04-11",
	} {
		if !strings.Contains(betas, want) {
			t.Fatalf("OAuth betas missing %s: %s", want, betas)
		}
	}
	plain := []byte(`{"model":"claude-opus-5-5","thinking":{"type":"adaptive","display":"updates"},"output_config":{"effort":"xhigh"},"messages":[{"role":"user","content":"hi"}]}`)
	plainBetas := anthropicClaudeCodeBetas(plain, true)
	if strings.Contains(plainBetas, "per-turn-control-2026-07-01") {
		t.Fatal("per-turn-control declared without message-level output_config")
	}
	if !strings.Contains(plainBetas, "thinking-display-updates-2026-08-18") {
		t.Fatalf("display updates missing beta: %s", plainBetas)
	}
	apiKeyBetas := anthropicClaudeCodeBetas(plain, false)
	if strings.Contains(apiKeyBetas, "extended-cache-ttl-2025-04-11") {
		t.Fatalf("API key declared extended-cache-ttl without body TTL: %s", apiKeyBetas)
	}
}

func TestSanitizeAnthropicBodyForBetaTokensStripsMessageOutputConfigWithoutBeta(t *testing.T) {
	t.Parallel()
	body := []byte(`{"model":"claude-opus-5-5","output_config":{"effort":"xhigh"},"messages":[{"role":"user","content":"hi"},{"role":"system","content":"turn","output_config":{"effort":"xhigh"}}]}`)
	got := sanitizeAnthropicBodyForBetaTokens(body, "claude-code-20250219,effort-2025-11-24")
	if gjson.GetBytes(got, "messages.1.output_config").Exists() {
		t.Fatalf("message output_config survived without beta: %s", got)
	}
	if gjson.GetBytes(got, "output_config.effort").String() != "xhigh" {
		t.Fatalf("top-level effort lost: %s", got)
	}
	kept := sanitizeAnthropicBodyForBetaTokens(body, "claude-code-20250219,per-turn-control-2026-07-01")
	if !gjson.GetBytes(kept, "messages.1.output_config").Exists() {
		t.Fatalf("message output_config dropped despite beta: %s", kept)
	}
	withUpdates := []byte(`{"thinking":{"type":"adaptive","display":"updates"},"messages":[{"role":"user","content":"hi"}]}`)
	strippedDisplay := sanitizeAnthropicBodyForBetaTokens(withUpdates, "claude-code-20250219")
	if gjson.GetBytes(strippedDisplay, "thinking.display").Exists() {
		t.Fatalf("updates display survived without beta: %s", strippedDisplay)
	}
	if gjson.GetBytes(strippedDisplay, "thinking.type").String() != "adaptive" {
		t.Fatalf("adaptive thinking lost while stripping display: %s", strippedDisplay)
	}
}

func TestApplyFinalAnthropicBetaBodyPolicyRewritesRequestBody(t *testing.T) {
	t.Parallel()
	body := []byte(`{"model":"claude-opus-5-5","messages":[{"role":"system","content":"turn","output_config":{"effort":"max"}}]}`)
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Anthropic-Beta", "claude-code-20250219")
	got, err := applyFinalAnthropicBetaBodyPolicy(req, body)
	if err != nil {
		t.Fatal(err)
	}
	if gjson.GetBytes(got, "messages.0.output_config").Exists() {
		t.Fatalf("policy left message output_config: %s", got)
	}
}
