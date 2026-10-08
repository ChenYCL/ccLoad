package githubcopilotauth

import "time"

const (
	// ChannelType is stored on persisted Copilot credentials.
	ChannelType = "github_copilot"

	// GitHubClientID is the official VS Code Copilot OAuth client.
	GitHubClientID = "Iv1.b507a08c87ecfe98"

	GitHubDeviceCodeURL   = "https://github.com/login/device/code"
	GitHubAccessTokenURL  = "https://github.com/login/oauth/access_token"
	GitHubCopilotTokenURL = "https://api.github.com/copilot_internal/v2/token"
	GitHubUserURL         = "https://api.github.com/user"

	// APIBaseURL is Copilot's default inference origin.
	APIBaseURL = "https://api.githubcopilot.com"

	OAuthScope = "read:user"

	EditorVersion        = "vscode/1.96.2"
	EditorPluginVersion  = "copilot-chat/0.23.2"
	CopilotUserAgent     = "GitHubCopilotChat/0.23.2"
	IntegrationID        = "vscode-chat"
	GitHubAPIVersion     = "2025-04-01"
	ClaudeAgentUserAgent = "vscode_claude_code/2.1.293 (external, sdk-ts, agent-sdk/0.3.293)"

	RefreshLead  = 2 * time.Minute
	PollTimeout  = 15 * time.Minute
	PollInterval = 5 * time.Second

	maxCredentialSize = 1 << 16
)

// DefaultModels seeds a channel when Copilot's catalog is unreachable.
var DefaultModels = []string{
	"claude-sonnet-4.5",
	"claude-opus-4.6",
	"claude-haiku-4.5",
	"claude-sonnet-4",
	"gpt-4.1",
	"gpt-4o",
}
