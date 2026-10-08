package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"ccLoad/internal/githubcopilotauth"
	"ccLoad/internal/model"
	"ccLoad/internal/storage"

	"github.com/gin-gonic/gin"
)

var githubCopilotChannelCreateMu sync.Mutex

func newGitHubCopilotOAuthChannel(name, credentialJSON, baseURL string, models []string) *model.Config {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = githubcopilotauth.APIBaseURL
	}
	if len(models) == 0 {
		models = append([]string(nil), githubcopilotauth.DefaultModels...)
	}
	return &model.Config{
		Name: name, AuthType: model.AuthTypeGitHubCopilotOAuth, OAuthCredential: credentialJSON,
		URLs:                  model.ChannelURLs{{URL: baseURL}},
		ProtocolTransformMode: model.ProtocolTransformModeAuto,
		Enabled:               true, CostMultiplier: 1, ModelEntries: oauthModelEntries(models),
	}
}

func (s *Server) commitGitHubCopilotCredential(
	ctx context.Context,
	credential *githubcopilotauth.Credential,
) (*model.Config, bool, error) {
	models := githubcopilotauth.DefaultModels
	if s != nil && s.githubCopilotService != nil && credential != nil {
		if listed, err := s.githubCopilotService.FetchModels(ctx, credential.CopilotToken, credential.Endpoint()); err != nil {
			log.Printf("[WARN] GitHub Copilot 模型目录不可用，新渠道使用内置列表: %v", err)
		} else if len(listed) > 0 {
			models = listed
		}
	}
	cfg, created, err := createOrUpdateGitHubCopilotChannel(ctx, s.store, credential, models)
	if err != nil {
		return nil, false, err
	}
	if s.githubCopilotCredentials != nil {
		s.githubCopilotCredentials.invalidate(cfg.ID)
	}
	s.invalidateChannelRelatedCache(cfg.ID)
	s.InvalidateChannelListCache()
	return cfg, created, nil
}

func createOrUpdateGitHubCopilotChannel(
	ctx context.Context,
	store storage.Store,
	credential *githubcopilotauth.Credential,
	models []string,
) (*model.Config, bool, error) {
	if store == nil || credential == nil {
		return nil, false, errors.New("persist github copilot credential: unavailable")
	}
	credentialJSON, err := credential.JSON()
	if err != nil {
		return nil, false, err
	}
	githubCopilotChannelCreateMu.Lock()
	defer githubCopilotChannelCreateMu.Unlock()
	configs, err := store.ListConfigs(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("list channels for github copilot credential: %w", err)
	}
	if existing, found, updateErr := updateExistingGitHubCopilotChannel(ctx, store, configs, credential); found || updateErr != nil {
		return existing, false, updateErr
	}
	name := uniqueGitHubCopilotChannelName(configs, githubCopilotChannelBaseName(credential))
	created, err := store.CreateConfig(ctx, newGitHubCopilotOAuthChannel(name, credentialJSON, credential.Endpoint(), models))
	if err != nil {
		return nil, false, fmt.Errorf("create github copilot channel: %w", err)
	}
	return created, true, nil
}

func updateExistingGitHubCopilotChannel(
	ctx context.Context,
	store storage.Store,
	configs []*model.Config,
	credential *githubcopilotauth.Credential,
) (*model.Config, bool, error) {
	login := credential.IdentityLogin()
	if login == "" {
		return nil, false, nil
	}
	for _, cfg := range configs {
		if cfg == nil || !cfg.UsesGitHubCopilotOAuth() {
			continue
		}
		existing, parseErr := githubcopilotauth.ParseCredential([]byte(cfg.OAuthCredential))
		if parseErr != nil {
			continue
		}
		if existing.IdentityLogin() != login {
			continue
		}
		merged, mergeErr := existing.MergeRefresh(credential)
		if mergeErr != nil {
			return nil, true, mergeErr
		}
		mergedJSON, encodeErr := merged.JSON()
		if encodeErr != nil {
			return nil, true, encodeErr
		}
		updated, updateErr := store.CompareAndSwapOAuthCredential(
			ctx, cfg.ID, model.AuthTypeGitHubCopilotOAuth, cfg.OAuthCredential, mergedJSON,
		)
		if updateErr != nil {
			return nil, true, updateErr
		}
		if !updated {
			return nil, true, errors.New("github copilot credential changed during reauthorization")
		}
		persisted, getErr := store.GetConfig(ctx, cfg.ID)
		return persisted, true, getErr
	}
	return nil, false, nil
}

func githubCopilotChannelBaseName(credential *githubcopilotauth.Credential) string {
	if credential != nil {
		if login := strings.TrimSpace(credential.Login); login != "" {
			return "GitHubCopilot-" + login
		}
	}
	return "GitHubCopilot"
}

func (s *Server) HandleRefreshGitHubCopilotCredential(c *gin.Context) {
	id, err := ParseInt64Param(c, "id")
	if err != nil {
		RespondErrorMsg(c, http.StatusBadRequest, "invalid channel id")
		return
	}
	cfg, err := s.store.GetConfig(c.Request.Context(), id)
	if err != nil {
		RespondErrorMsg(c, http.StatusNotFound, "channel not found")
		return
	}
	if !cfg.UsesGitHubCopilotOAuth() {
		RespondErrorMsg(c, http.StatusConflict, "channel does not use GitHub Copilot OAuth")
		return
	}
	if s.githubCopilotCredentials == nil {
		RespondErrorMsg(c, http.StatusServiceUnavailable, "GitHub Copilot credential refresh is unavailable")
		return
	}
	credential, err := s.githubCopilotCredentials.credential(c.Request.Context(), cfg, true)
	if err != nil {
		RespondError(c, http.StatusBadGateway, err)
		return
	}
	s.InvalidateChannelListCache()
	RespondJSON(c, http.StatusOK, gin.H{"oauth_credential": credential})
}

func uniqueGitHubCopilotChannelName(configs []*model.Config, base string) string {
	used := make(map[string]struct{}, len(configs))
	for _, cfg := range configs {
		if cfg != nil {
			used[cfg.Name] = struct{}{}
		}
	}
	if _, exists := used[base]; !exists {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
}
