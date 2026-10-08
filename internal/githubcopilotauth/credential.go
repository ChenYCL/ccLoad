package githubcopilotauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Credential is the private GitHub Copilot payload persisted on a channel.
//
// GitHubToken is the long-lived OAuth token. CopilotToken is the short-lived
// inference key (~30 minutes) exchanged from GitHubToken.
type Credential struct {
	Type             string          `json:"type"`
	GitHubToken      string          `json:"github_token"`
	CopilotToken     string          `json:"copilot_token"`
	CopilotExpiresAt int64           `json:"copilot_expires_at,omitempty"`
	APIBase          string          `json:"api_base,omitempty"`
	Login            string          `json:"login,omitempty"`
	Name             string          `json:"name,omitempty"`
	SKU              string          `json:"sku,omitempty"`
	LastRefresh      string          `json:"last_refresh,omitempty"`
	OAuthUsage       json.RawMessage `json:"oauth_usage,omitempty"`
}

// ParseCredential decodes and normalizes one persisted Copilot credential.
func ParseCredential(raw []byte) (*Credential, error) {
	if len(raw) == 0 {
		return nil, errors.New("github copilot credential is empty")
	}
	if len(raw) > maxCredentialSize {
		return nil, fmt.Errorf("github copilot credential exceeds %d bytes", maxCredentialSize)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	var credential Credential
	if err := decoder.Decode(&credential); err != nil {
		return nil, fmt.Errorf("decode github copilot credential: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("github copilot credential contains trailing JSON")
	}
	if err := credential.Normalize(); err != nil {
		return nil, err
	}
	return &credential, nil
}

// Normalize validates and canonicalizes a credential in place.
func (c *Credential) Normalize() error {
	if c == nil {
		return errors.New("github copilot credential is nil")
	}
	c.Type = strings.ToLower(strings.TrimSpace(c.Type))
	if c.Type == "" || c.Type == "copilot" || c.Type == "github" {
		c.Type = ChannelType
	}
	if c.Type != ChannelType {
		return fmt.Errorf("unsupported github copilot credential type %q", c.Type)
	}
	c.GitHubToken = strings.TrimSpace(c.GitHubToken)
	c.CopilotToken = strings.TrimSpace(c.CopilotToken)
	c.APIBase = strings.TrimRight(strings.TrimSpace(c.APIBase), "/")
	c.Login = strings.TrimSpace(c.Login)
	c.Name = strings.TrimSpace(c.Name)
	c.SKU = strings.TrimSpace(c.SKU)
	c.LastRefresh = strings.TrimSpace(c.LastRefresh)
	if c.GitHubToken == "" {
		return errors.New("github copilot credential is missing github_token")
	}
	if strings.ContainsAny(c.GitHubToken, " \r\n\t") {
		return errors.New("github copilot credential has an invalid github_token")
	}
	if c.APIBase == "" {
		c.APIBase = APIBaseURL
	}
	if c.LastRefresh != "" {
		parsed, err := time.Parse(time.RFC3339, c.LastRefresh)
		if err != nil {
			return errors.New("github copilot credential has invalid last_refresh")
		}
		c.LastRefresh = parsed.UTC().Format(time.RFC3339)
	}
	return nil
}

// Endpoint is the Copilot inference origin for this credential.
func (c *Credential) Endpoint() string {
	if c == nil || strings.TrimSpace(c.APIBase) == "" {
		return APIBaseURL
	}
	return strings.TrimRight(strings.TrimSpace(c.APIBase), "/")
}

// NeedsRefresh reports whether the short-lived Copilot token should be renewed.
func (c *Credential) NeedsRefresh(now time.Time) bool {
	if c == nil || c.CopilotToken == "" || c.CopilotExpiresAt <= 0 {
		return true
	}
	return now.Add(RefreshLead).Unix() >= c.CopilotExpiresAt
}

// IdentityLogin is the GitHub account used to deduplicate channels.
func (c *Credential) IdentityLogin() string {
	if c == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(c.Login))
}

// MergeRefresh keeps identity metadata that a refreshed token omits.
func (c *Credential) MergeRefresh(refreshed *Credential) (*Credential, error) {
	if c == nil || refreshed == nil {
		return nil, errors.New("github copilot refresh credential is nil")
	}
	merged := *refreshed
	if strings.TrimSpace(merged.GitHubToken) == "" {
		merged.GitHubToken = c.GitHubToken
	}
	if strings.TrimSpace(merged.Login) == "" {
		merged.Login = c.Login
	}
	if strings.TrimSpace(merged.Name) == "" {
		merged.Name = c.Name
	}
	if len(merged.OAuthUsage) == 0 {
		merged.OAuthUsage = append(json.RawMessage(nil), c.OAuthUsage...)
	}
	if err := merged.Normalize(); err != nil {
		return nil, err
	}
	return &merged, nil
}

// JSON returns the canonical private database payload.
func (c *Credential) JSON() (string, error) {
	if err := c.Normalize(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encode github copilot credential: %w", err)
	}
	return string(raw), nil
}
