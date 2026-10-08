package app

import (
	"net/http"
	"strings"

	"ccLoad/internal/githubcopilotauth"
	"ccLoad/internal/model"
	"ccLoad/internal/protocol"

	"github.com/google/uuid"
)

func isGitHubCopilotAnthropicRequest(cfg *model.Config, upstream protocol.Protocol, requestPath string) bool {
	return cfg != nil && cfg.UsesGitHubCopilotOAuth() && isAnthropicMessagesRequest(upstream, requestPath)
}

func injectGitHubCopilotHeaders(req *http.Request, cfg *model.Config, copilotToken string, incoming http.Header, upstream protocol.Protocol) {
	if req == nil {
		return
	}
	token := strings.TrimSpace(copilotToken)
	sessionID := strings.TrimSpace(anthropicHeaderValue(incoming, "X-Claude-Code-Session-Id"))
	if sessionID == "" {
		sessionID = strings.TrimSpace(anthropicHeaderValue(incoming, "Session-Id"))
	}
	requestID := strings.TrimSpace(anthropicHeaderValue(incoming, "X-Request-Id"))
	if requestID == "" {
		requestID = uuid.NewString()
	}
	var headers http.Header
	if upstream == protocol.Anthropic {
		headers = githubcopilotauth.AnthropicMessagesHeaders(token, sessionID, requestID)
		if betas := strings.TrimSpace(anthropicHeaderValue(incoming, "Anthropic-Beta")); betas != "" {
			headers.Set("Anthropic-Beta", betas)
		}
	} else {
		headers = githubcopilotauth.CopilotHeaders(token)
		if sessionID != "" {
			headers.Set("X-Client-Session-Id", sessionID)
			headers.Set("X-Interaction-Id", sessionID)
		}
		headers.Set("X-Agent-Task-Id", requestID)
		if upstream == protocol.Codex {
			headers.Set("Openai-Intent", "conversation-edits")
			headers.Set("Copilot-Integration-Id", "copilot-developer-cli")
		}
	}
	req.Header = headers
	_ = cfg
}
