package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"ccLoad/internal/githubcopilotauth"

	"github.com/gin-gonic/gin"
)

const (
	githubCopilotOAuthSessionTTL  = 15 * time.Minute
	githubCopilotOAuthTerminalTTL = 2 * time.Minute
)

type githubCopilotOAuthStartResponse struct {
	URL      string `json:"url"`
	State    string `json:"state"`
	Status   string `json:"status"`
	UserCode string `json:"user_code,omitempty"`
}

type githubCopilotOAuthStatusResponse struct {
	State       string `json:"state"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
	ChannelID   int64  `json:"channel_id,omitempty"`
	ChannelName string `json:"channel_name,omitempty"`
	UserCode    string `json:"user_code,omitempty"`
}

type githubCopilotOAuthCancelRequest struct {
	State string `json:"state"`
}

func (r *githubCopilotOAuthCancelRequest) Validate() error {
	if strings.TrimSpace(r.State) == "" {
		return errors.New("state is required")
	}
	return nil
}

type githubCopilotOAuthSession struct {
	state            string
	adminSessionHash string
	ctx              context.Context
	cancel           context.CancelFunc
	status           string
	errorMsg         string
	channelID        int64
	channelName      string
	userCode         string
	createdAt        time.Time
	finishedAt       time.Time
}

type githubCopilotOAuthManager struct {
	mu          sync.Mutex
	service     *githubcopilotauth.Service
	commit      func(context.Context, *githubcopilotauth.Credential) (int64, string, error)
	baseCtx     context.Context
	now         func() time.Time
	sleep       func(context.Context, time.Duration)
	sessions    map[string]*githubCopilotOAuthSession
	activeByID  map[string]string
	stopJanitor chan struct{}
	janitorDone chan struct{}
	closeOnce   sync.Once
	closed      bool
	pollers     sync.WaitGroup
}

func newGitHubCopilotOAuthManager(
	baseCtx context.Context,
	service *githubcopilotauth.Service,
	commit func(context.Context, *githubcopilotauth.Credential) (int64, string, error),
) *githubCopilotOAuthManager {
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	manager := &githubCopilotOAuthManager{
		service: service, commit: commit, baseCtx: baseCtx,
		now: time.Now, sleep: sleepWithContext,
		sessions: make(map[string]*githubCopilotOAuthSession), activeByID: make(map[string]string),
		stopJanitor: make(chan struct{}), janitorDone: make(chan struct{}),
	}
	go manager.runJanitor()
	return manager
}

func (m *githubCopilotOAuthManager) start(ctx context.Context, adminSessionHash string) (githubCopilotOAuthStartResponse, error) {
	if m == nil || m.service == nil || m.commit == nil {
		return githubCopilotOAuthStartResponse{}, errors.New("github copilot OAuth is unavailable")
	}
	adminSessionHash = strings.TrimSpace(adminSessionHash)
	if adminSessionHash == "" {
		return githubCopilotOAuthStartResponse{}, errors.New("github copilot OAuth requires an administrator session")
	}
	flow, err := m.service.StartDeviceFlow(ctx)
	if err != nil {
		return githubCopilotOAuthStartResponse{}, err
	}
	authorizeURL := strings.TrimSpace(flow.VerificationURIComplete)
	if authorizeURL == "" {
		authorizeURL = strings.TrimSpace(flow.VerificationURI)
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return githubCopilotOAuthStartResponse{}, errors.New("github copilot OAuth is unavailable")
	}
	m.pruneExpiredSessionsLocked()
	if old := m.sessions[m.activeByID[adminSessionHash]]; old != nil && githubCopilotOAuthSessionCancelable(old.status) {
		m.finishSessionLocked(old, "cancelled", "", 0, "")
	}
	sessionCtx, cancel := context.WithCancel(m.baseCtx)
	session := &githubCopilotOAuthSession{
		state: flow.DeviceCode, adminSessionHash: adminSessionHash,
		ctx: sessionCtx, cancel: cancel, status: "pending",
		userCode: flow.UserCode, createdAt: m.now(),
	}
	m.sessions[session.state] = session
	m.activeByID[adminSessionHash] = session.state
	m.pollers.Add(1)
	m.mu.Unlock()

	go m.run(session, flow)
	return githubCopilotOAuthStartResponse{
		URL: authorizeURL, State: session.state, Status: "pending", UserCode: flow.UserCode,
	}, nil
}

func (m *githubCopilotOAuthManager) run(session *githubCopilotOAuthSession, flow *githubcopilotauth.DeviceFlow) {
	defer m.pollers.Done()
	interval := time.Duration(flow.Interval) * time.Second
	if interval < time.Second {
		interval = githubcopilotauth.PollInterval
	}
	deadline := m.now().Add(time.Duration(flow.ExpiresIn) * time.Second)
	if flow.ExpiresIn <= 0 {
		deadline = m.now().Add(githubcopilotauth.PollTimeout)
	}
	for m.now().Before(deadline) {
		if session.ctx.Err() != nil {
			return
		}
		token, err := m.service.PollAccessToken(session.ctx, flow.DeviceCode)
		if err != nil {
			if errors.Is(err, githubcopilotauth.ErrSlowDown) {
				interval += 5 * time.Second
				m.sleep(session.ctx, interval)
				continue
			}
			if session.ctx.Err() != nil {
				return
			}
			m.finish(session, "error", err.Error(), 0, "")
			return
		}
		if token == "" {
			m.sleep(session.ctx, interval)
			continue
		}
		m.completeAuthorization(session, token)
		return
	}
	if session.ctx.Err() == nil {
		m.finish(session, "error", "github authorization timed out", 0, "")
	}
}

func (m *githubCopilotOAuthManager) completeAuthorization(session *githubCopilotOAuthSession, githubToken string) {
	m.mu.Lock()
	if session.status != "pending" {
		m.mu.Unlock()
		return
	}
	session.status = "committing"
	if m.activeByID[session.adminSessionHash] == session.state {
		delete(m.activeByID, session.adminSessionHash)
	}
	m.mu.Unlock()

	credential, err := m.service.CompleteLogin(session.ctx, githubToken)
	if err != nil {
		m.finish(session, "error", err.Error(), 0, "")
		return
	}
	channelID, channelName, err := m.commit(session.ctx, credential)
	if err != nil {
		m.finish(session, "error", err.Error(), 0, "")
		return
	}
	m.finish(session, "complete", "", channelID, channelName)
}

func (m *githubCopilotOAuthManager) status(adminSessionHash, state string) (githubCopilotOAuthStatusResponse, bool) {
	adminSessionHash = strings.TrimSpace(adminSessionHash)
	state = strings.TrimSpace(state)
	m.mu.Lock()
	defer m.mu.Unlock()
	session := m.sessions[state]
	if session == nil || session.adminSessionHash != adminSessionHash {
		return githubCopilotOAuthStatusResponse{}, false
	}
	return githubCopilotOAuthStatusResponse{
		State: session.state, Status: session.status, Error: session.errorMsg,
		ChannelID: session.channelID, ChannelName: session.channelName, UserCode: session.userCode,
	}, true
}

func (m *githubCopilotOAuthManager) cancel(adminSessionHash, state string) error {
	adminSessionHash = strings.TrimSpace(adminSessionHash)
	state = strings.TrimSpace(state)
	m.mu.Lock()
	session := m.sessions[state]
	if session == nil || session.adminSessionHash != adminSessionHash {
		m.mu.Unlock()
		return errors.New("github copilot OAuth session not found")
	}
	if !githubCopilotOAuthSessionCancelable(session.status) {
		m.mu.Unlock()
		return errors.New("github copilot OAuth session cannot be cancelled")
	}
	m.finishSessionLocked(session, "cancelled", "", 0, "")
	cancel := session.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

func githubCopilotOAuthSessionCancelable(status string) bool {
	return status == "pending" || status == "committing"
}

func (m *githubCopilotOAuthManager) finish(session *githubCopilotOAuthSession, status, errorMsg string, channelID int64, channelName string) {
	m.mu.Lock()
	m.finishSessionLocked(session, status, errorMsg, channelID, channelName)
	m.mu.Unlock()
}

func (m *githubCopilotOAuthManager) finishSessionLocked(session *githubCopilotOAuthSession, status, errorMsg string, channelID int64, channelName string) {
	if session == nil || session.status == "complete" || session.status == "error" || session.status == "cancelled" {
		if session != nil && status != session.status && githubCopilotOAuthSessionCancelable(session.status) {
			session.status = status
			session.errorMsg = errorMsg
			session.channelID = channelID
			session.channelName = channelName
			session.finishedAt = m.now()
		}
		return
	}
	session.status = status
	session.errorMsg = errorMsg
	session.channelID = channelID
	session.channelName = channelName
	session.finishedAt = m.now()
	if m.activeByID[session.adminSessionHash] == session.state {
		delete(m.activeByID, session.adminSessionHash)
	}
}

func (m *githubCopilotOAuthManager) pruneExpiredSessionsLocked() {
	now := m.now()
	for state, session := range m.sessions {
		ttl := githubCopilotOAuthSessionTTL
		if session.status == "complete" || session.status == "error" || session.status == "cancelled" {
			ttl = githubCopilotOAuthTerminalTTL
		}
		anchor := session.createdAt
		if !session.finishedAt.IsZero() {
			anchor = session.finishedAt
		}
		if now.Sub(anchor) < ttl {
			continue
		}
		if githubCopilotOAuthSessionCancelable(session.status) && session.cancel != nil {
			session.cancel()
		}
		delete(m.sessions, state)
		if m.activeByID[session.adminSessionHash] == state {
			delete(m.activeByID, session.adminSessionHash)
		}
	}
}

func (m *githubCopilotOAuthManager) runJanitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer close(m.janitorDone)
	for {
		select {
		case <-m.stopJanitor:
			return
		case <-ticker.C:
			m.mu.Lock()
			m.pruneExpiredSessionsLocked()
			m.mu.Unlock()
		}
	}
}

func (m *githubCopilotOAuthManager) close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		close(m.stopJanitor)
		var cancels []context.CancelFunc
		for _, session := range m.sessions {
			if session.cancel != nil {
				cancels = append(cancels, session.cancel)
			}
		}
		m.sessions = make(map[string]*githubCopilotOAuthSession)
		m.activeByID = make(map[string]string)
		m.mu.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
		m.pollers.Wait()
		<-m.janitorDone
	})
}

func (s *Server) HandleStartGitHubCopilotOAuth(c *gin.Context) {
	adminSessionHash, ok := xaiAdminSessionHash(c)
	if !ok {
		RespondErrorMsg(c, http.StatusUnauthorized, "administrator session is unavailable")
		return
	}
	if s.githubCopilotOAuth == nil {
		RespondErrorMsg(c, http.StatusServiceUnavailable, "github copilot OAuth is unavailable")
		return
	}
	response, err := s.githubCopilotOAuth.start(c.Request.Context(), adminSessionHash)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, err)
		return
	}
	RespondJSON(c, http.StatusOK, response)
}

func (s *Server) HandleGitHubCopilotOAuthStatus(c *gin.Context) {
	adminSessionHash, ok := xaiAdminSessionHash(c)
	if !ok || s.githubCopilotOAuth == nil {
		RespondErrorMsg(c, http.StatusNotFound, "github copilot OAuth session not found")
		return
	}
	status, exists := s.githubCopilotOAuth.status(adminSessionHash, c.Query("state"))
	if !exists {
		RespondErrorMsg(c, http.StatusNotFound, "github copilot OAuth session not found")
		return
	}
	RespondJSON(c, http.StatusOK, status)
}

func (s *Server) HandleCancelGitHubCopilotOAuth(c *gin.Context) {
	adminSessionHash, ok := xaiAdminSessionHash(c)
	if !ok || s.githubCopilotOAuth == nil {
		RespondErrorMsg(c, http.StatusNotFound, "github copilot OAuth session not found")
		return
	}
	var request githubCopilotOAuthCancelRequest
	if err := BindAndValidate(c, &request); err != nil {
		RespondError(c, http.StatusBadRequest, err)
		return
	}
	if err := s.githubCopilotOAuth.cancel(adminSessionHash, request.State); err != nil {
		RespondError(c, http.StatusConflict, err)
		return
	}
	RespondJSON(c, http.StatusOK, githubCopilotOAuthStatusResponse{State: strings.TrimSpace(request.State), Status: "cancelled"})
}
