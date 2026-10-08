package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"ccLoad/internal/githubcopilotauth"
	"ccLoad/internal/model"
	"ccLoad/internal/storage"

	"golang.org/x/sync/singleflight"
)

type githubCopilotCredentialManager struct {
	mu               sync.RWMutex
	entries          map[int64]*githubcopilotauth.Credential
	refreshes        singleflight.Group
	refreshTracker   *oauthCredentialRefreshTracker
	store            storage.Store
	clientFor        func(*model.Config) *http.Client
	invalidateConfig func(int64)
	now              func() time.Time
}

func newGitHubCopilotCredentialManager(
	store storage.Store,
	clientFor func(*model.Config) *http.Client,
	invalidate func(int64),
) *githubCopilotCredentialManager {
	return &githubCopilotCredentialManager{
		entries: make(map[int64]*githubcopilotauth.Credential), store: store,
		clientFor: clientFor, invalidateConfig: invalidate, now: time.Now,
	}
}

func (m *githubCopilotCredentialManager) invalidate(channelID int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	delete(m.entries, channelID)
	m.mu.Unlock()
}

func (m *githubCopilotCredentialManager) cache(channelID int64, credential *githubcopilotauth.Credential) {
	if m == nil || credential == nil {
		return
	}
	cloned := *credential
	m.mu.Lock()
	if m.entries == nil {
		m.entries = make(map[int64]*githubcopilotauth.Credential)
	}
	m.entries[channelID] = &cloned
	m.mu.Unlock()
}

func (m *githubCopilotCredentialManager) cachedOrParse(cfg *model.Config) (*githubcopilotauth.Credential, error) {
	m.mu.RLock()
	cached := m.entries[cfg.ID]
	m.mu.RUnlock()
	if cached != nil {
		clone := *cached
		return &clone, nil
	}
	parsed, err := githubcopilotauth.ParseCredential([]byte(cfg.OAuthCredential))
	if err != nil {
		return nil, fmt.Errorf("parse github copilot credential for channel %d: %w", cfg.ID, err)
	}
	m.cache(cfg.ID, parsed)
	clone := *parsed
	return &clone, nil
}

func (m *githubCopilotCredentialManager) credential(
	ctx context.Context,
	cfg *model.Config,
	forceRefresh bool,
) (*githubcopilotauth.Credential, error) {
	if m == nil || m.store == nil || cfg == nil || !cfg.UsesGitHubCopilotOAuth() {
		return nil, errors.New("github copilot credential manager is unavailable")
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	credential, err := m.cachedOrParse(cfg)
	if err != nil {
		return nil, err
	}
	now := m.now()
	if !forceRefresh && !credential.NeedsRefresh(now) {
		clone := *credential
		return &clone, nil
	}
	rejected := credential.CopilotToken
	resultCh := m.refreshes.DoChan(oauthCredentialRefreshSingleflightKey(cfg.ID, rejected, forceRefresh), func() (any, error) {
		refreshCtx := context.Background()
		if m.refreshTracker != nil {
			trackedCtx, done, beginErr := m.refreshTracker.begin()
			if beginErr != nil {
				return nil, beginErr
			}
			defer done()
			refreshCtx = trackedCtx
		} else if ctx != nil {
			refreshCtx = context.WithoutCancel(ctx)
		}
		currentCfg, getErr := m.store.GetConfig(refreshCtx, cfg.ID)
		if getErr != nil {
			return nil, fmt.Errorf("reload github copilot credential: %w", getErr)
		}
		current, parseErr := githubcopilotauth.ParseCredential([]byte(currentCfg.OAuthCredential))
		if parseErr != nil {
			return nil, fmt.Errorf("parse github copilot credential for channel %d: %w", currentCfg.ID, parseErr)
		}
		if !forceRefresh && !current.NeedsRefresh(m.now()) {
			m.cache(currentCfg.ID, current)
			clone := *current
			return &clone, nil
		}
		client := http.DefaultClient
		if m.clientFor != nil {
			client = m.clientFor(currentCfg)
		}
		service := githubcopilotauth.NewService(client)
		token, refreshErr := service.RefreshCopilotToken(refreshCtx, current.GitHubToken)
		if refreshErr != nil {
			return nil, fmt.Errorf("refresh github copilot token for channel %d: %w", currentCfg.ID, refreshErr)
		}
		refreshed := &githubcopilotauth.Credential{
			Type: githubcopilotauth.ChannelType, GitHubToken: current.GitHubToken,
			CopilotToken: token.Token, CopilotExpiresAt: token.ExpiresAt,
			APIBase: token.APIBase, SKU: token.SKU, Login: current.Login, Name: current.Name,
			LastRefresh: m.now().UTC().Format(time.RFC3339),
		}
		merged, mergeErr := current.MergeRefresh(refreshed)
		if mergeErr != nil {
			return nil, mergeErr
		}
		encoded, encodeErr := merged.JSON()
		if encodeErr != nil {
			return nil, encodeErr
		}
		updated, swapErr := m.store.CompareAndSwapOAuthCredential(
			refreshCtx, currentCfg.ID, model.AuthTypeGitHubCopilotOAuth, currentCfg.OAuthCredential, encoded,
		)
		if swapErr != nil {
			return nil, swapErr
		}
		if !updated {
			latest, latestErr := m.store.GetConfig(refreshCtx, currentCfg.ID)
			if latestErr != nil {
				return nil, latestErr
			}
			parsed, parseLatest := githubcopilotauth.ParseCredential([]byte(latest.OAuthCredential))
			if parseLatest != nil {
				return nil, parseLatest
			}
			m.cache(latest.ID, parsed)
			return parsed, nil
		}
		m.cache(currentCfg.ID, merged)
		if m.invalidateConfig != nil {
			m.invalidateConfig(currentCfg.ID)
		}
		return merged, nil
	})
	var result singleflight.Result
	if ctx == nil {
		result = <-resultCh
	} else {
		select {
		case result = <-resultCh:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if result.Err != nil {
		return nil, result.Err
	}
	credential, _ = result.Val.(*githubcopilotauth.Credential)
	if credential == nil {
		return nil, errors.New("github copilot credential refresh returned nothing")
	}
	clone := *credential
	return &clone, nil
}
