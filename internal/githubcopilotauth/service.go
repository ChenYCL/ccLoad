package githubcopilotauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Service talks to GitHub OAuth and the Copilot control plane.
type Service struct {
	Client          *http.Client
	DeviceCodeURL   string
	AccessTokenURL  string
	CopilotTokenURL string
	UserURL         string
	Now             func() time.Time
}

// NewService returns the production Copilot service.
func NewService(client *http.Client) *Service {
	if client == nil {
		client = http.DefaultClient
	}
	return &Service{
		Client: client, DeviceCodeURL: GitHubDeviceCodeURL, AccessTokenURL: GitHubAccessTokenURL,
		CopilotTokenURL: GitHubCopilotTokenURL, UserURL: GitHubUserURL, Now: time.Now,
	}
}

// DeviceFlow is one pending GitHub device authorization.
type DeviceFlow struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int
	Interval                int
}

// CopilotToken is the short-lived inference credential.
type CopilotToken struct {
	Token     string
	ExpiresAt int64
	APIBase   string
	SKU       string
}

type responseError struct {
	operation string
	status    int
	body      string
}

func (e *responseError) Error() string {
	return fmt.Sprintf("github copilot %s returned HTTP %d", e.operation, e.status)
}
func (e *responseError) StatusCode() int              { return e.status }
func (e *responseError) UpstreamResponseBody() string { return e.body }

func (s *Service) client() *http.Client {
	if s == nil || s.Client == nil {
		return http.DefaultClient
	}
	return s.Client
}

func (s *Service) now() time.Time {
	if s == nil || s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

func githubHeaders(githubToken string) http.Header {
	h := make(http.Header)
	h.Set("Accept", "application/json")
	h.Set("Content-Type", "application/json")
	h.Set("Editor-Version", EditorVersion)
	h.Set("Editor-Plugin-Version", EditorPluginVersion)
	h.Set("User-Agent", CopilotUserAgent)
	if strings.TrimSpace(githubToken) != "" {
		h.Set("Authorization", "token "+strings.TrimSpace(githubToken))
	}
	return h
}

// CopilotHeaders is the inference identity Copilot expects on chat/messages.
func CopilotHeaders(copilotToken string) http.Header {
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+strings.TrimSpace(copilotToken))
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	h.Set("User-Agent", CopilotUserAgent)
	h.Set("Openai-Intent", "conversation-agent")
	h.Set("Copilot-Integration-Id", IntegrationID)
	h.Set("X-Github-Api-Version", GitHubAPIVersion)
	h.Set("Editor-Version", EditorVersion)
	h.Set("Editor-Plugin-Version", EditorPluginVersion)
	return h
}

// AnthropicMessagesHeaders is Copilot's native Claude /v1/messages identity.
func AnthropicMessagesHeaders(copilotToken, sessionID, requestID string) http.Header {
	h := CopilotHeaders(copilotToken)
	h.Set("User-Agent", ClaudeAgentUserAgent)
	h.Set("Openai-Intent", "messages-proxy")
	h.Set("X-Interaction-Type", "messages-proxy")
	h.Set("Anthropic-Version", "2023-06-01")
	h.Set("X-Initiator", "user")
	if strings.TrimSpace(requestID) != "" {
		h.Set("X-Agent-Task-Id", requestID)
		h.Set("X-Request-Id", requestID)
	}
	if strings.TrimSpace(sessionID) != "" {
		h.Set("X-Interaction-Id", sessionID)
		h.Set("X-Client-Session-Id", sessionID)
	}
	return h
}

// StartDeviceFlow begins GitHub's OAuth device code login.
func (s *Service) StartDeviceFlow(ctx context.Context) (*DeviceFlow, error) {
	payload, err := json.Marshal(map[string]string{
		"client_id": GitHubClientID,
		"scope":     OAuthScope,
	})
	if err != nil {
		return nil, fmt.Errorf("encode github device flow: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.DeviceCodeURL, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header = githubHeaders("")
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("github device flow: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return nil, &responseError{operation: "device_code", status: resp.StatusCode, body: string(body)}
	}
	var parsed struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode github device flow: %w", err)
	}
	if strings.TrimSpace(parsed.DeviceCode) == "" || strings.TrimSpace(parsed.UserCode) == "" {
		return nil, errors.New("github device flow did not return a user code")
	}
	if parsed.Interval <= 0 {
		parsed.Interval = 5
	}
	if parsed.ExpiresIn <= 0 {
		parsed.ExpiresIn = 900
	}
	return &DeviceFlow{
		DeviceCode: parsed.DeviceCode, UserCode: parsed.UserCode,
		VerificationURI: parsed.VerificationURI, VerificationURIComplete: parsed.VerificationURIComplete,
		ExpiresIn: parsed.ExpiresIn, Interval: parsed.Interval,
	}, nil
}

// PollAccessToken waits for one device authorization. authorization_pending
// returns ("", nil) so the caller can sleep and retry.
func (s *Service) PollAccessToken(ctx context.Context, deviceCode string) (string, error) {
	form := url.Values{}
	form.Set("client_id", GitHubClientID)
	form.Set("device_code", strings.TrimSpace(deviceCode))
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.AccessTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("github access token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var parsed struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decode github access token: %w", err)
	}
	switch parsed.Error {
	case "", "success":
		if strings.TrimSpace(parsed.AccessToken) == "" {
			if resp.StatusCode >= 300 {
				return "", &responseError{operation: "access_token", status: resp.StatusCode, body: string(body)}
			}
			return "", errors.New("github access token is empty")
		}
		return strings.TrimSpace(parsed.AccessToken), nil
	case "authorization_pending":
		return "", nil
	case "slow_down":
		return "", ErrSlowDown
	case "expired_token", "access_denied":
		return "", fmt.Errorf("github authorization %s", parsed.Error)
	default:
		if parsed.Error != "" {
			return "", fmt.Errorf("github authorization: %s", parsed.Error)
		}
		return "", &responseError{operation: "access_token", status: resp.StatusCode, body: string(body)}
	}
}

// ErrSlowDown means GitHub asked the poller to wait longer.
var ErrSlowDown = errors.New("github authorization slow_down")

// RefreshCopilotToken exchanges a GitHub OAuth token for a Copilot API key.
func (s *Service) RefreshCopilotToken(ctx context.Context, githubToken string) (*CopilotToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.CopilotTokenURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = githubHeaders(githubToken)
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("github copilot token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, &responseError{operation: "copilot_token", status: resp.StatusCode, body: string(body)}
	}
	var parsed struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
		SKU       string `json:"sku"`
		Endpoints struct {
			API string `json:"api"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode github copilot token: %w", err)
	}
	if strings.TrimSpace(parsed.Token) == "" {
		return nil, errors.New("github copilot token is empty")
	}
	apiBase := strings.TrimRight(strings.TrimSpace(parsed.Endpoints.API), "/")
	if apiBase == "" {
		apiBase = APIBaseURL
	}
	return &CopilotToken{
		Token: parsed.Token, ExpiresAt: parsed.ExpiresAt, APIBase: apiBase, SKU: strings.TrimSpace(parsed.SKU),
	}, nil
}

// FetchUser returns the GitHub login for this OAuth token.
func (s *Service) FetchUser(ctx context.Context, githubToken string) (login, name string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.UserURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(githubToken))
	req.Header.Set("User-Agent", CopilotUserAgent)
	resp, err := s.client().Do(req)
	if err != nil {
		return "", "", fmt.Errorf("github user: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return "", "", &responseError{operation: "user", status: resp.StatusCode, body: string(body)}
	}
	var parsed struct {
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", "", fmt.Errorf("decode github user: %w", err)
	}
	return strings.TrimSpace(parsed.Login), strings.TrimSpace(parsed.Name), nil
}

// FetchModels lists Copilot models available to this API key.
func (s *Service) FetchModels(ctx context.Context, copilotToken, apiBase string) ([]string, error) {
	apiBase = strings.TrimRight(strings.TrimSpace(apiBase), "/")
	if apiBase == "" {
		apiBase = APIBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header = CopilotHeaders(copilotToken)
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("github copilot models: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, &responseError{operation: "models", status: resp.StatusCode, body: string(body)}
	}
	var parsed struct {
		Data []struct {
			ID     string `json:"id"`
			Policy struct {
				State string `json:"state"`
			} `json:"policy"`
			ModelPickerEnabled *bool `json:"model_picker_enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode github copilot models: %w", err)
	}
	models := make([]string, 0, len(parsed.Data))
	seen := map[string]struct{}{}
	for _, item := range parsed.Data {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		if state := strings.ToLower(strings.TrimSpace(item.Policy.State)); state != "" && state != "enabled" {
			continue
		}
		if item.ModelPickerEnabled != nil && !*item.ModelPickerEnabled {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		models = append(models, id)
	}
	return models, nil
}

// CompleteLogin exchanges a GitHub OAuth token for a persisted credential.
func (s *Service) CompleteLogin(ctx context.Context, githubToken string) (*Credential, error) {
	githubToken = strings.TrimSpace(githubToken)
	if githubToken == "" {
		return nil, errors.New("github token is required")
	}
	copilot, err := s.RefreshCopilotToken(ctx, githubToken)
	if err != nil {
		return nil, err
	}
	login, name, userErr := s.FetchUser(ctx, githubToken)
	if userErr != nil {
		login, name = "", ""
	}
	credential := &Credential{
		Type: ChannelType, GitHubToken: githubToken, CopilotToken: copilot.Token,
		CopilotExpiresAt: copilot.ExpiresAt, APIBase: copilot.APIBase,
		Login: login, Name: name, SKU: copilot.SKU,
		LastRefresh: s.now().UTC().Format(time.RFC3339),
	}
	if err := credential.Normalize(); err != nil {
		return nil, err
	}
	return credential, nil
}
