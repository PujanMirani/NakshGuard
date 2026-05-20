package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type TokenSample struct {
	tokens int
	at     time.Time
}

type AgentSession struct {
	mu      sync.Mutex
	AgentID string

	RequestCount    int
	TotalTokens     int
	StartTime       time.Time
	LastSeen        time.Time
	LastRequestTime time.Time

	Config     AgentConfig
	ConfigHash string

	RateLimiter *SlidingWindowRateLimiter

	tokenSamples []TokenSample // recent input sizes, for CVE
	window       struct {
		tokens int
		start  time.Time
	}

	recentHashes []struct { // prompt hashes for repeat detection
		hash string
		at   time.Time
	}
}

var (
	sessions   = make(map[string]*AgentSession)
	sessionsMu sync.Mutex
)

func getOrCreateSession(agentID string) *AgentSession {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	if s, ok := sessions[agentID]; ok {
		// don't touch s's fields here — sessionsMu doesn't protect s.mu,
		// and another goroutine could be mid-ProcessRequest right now
		return s
	}

	globalCfg := GetConfig()
	agentCfg, cfgHash := GetAgentConfig(agentID)

	s := &AgentSession{
		AgentID:    agentID,
		StartTime:  time.Now(),
		LastSeen:   time.Now(),
		Config:     agentCfg,
		ConfigHash: cfgHash,
		RateLimiter: NewRateLimiter(
			globalCfg.GlobalSettings.RateLimiter.MaxRequests,
			globalCfg.GlobalSettings.RateLimiter.WindowSeconds,
		),
	}
	s.window.start = time.Now()

	sessions[agentID] = s
	fmt.Printf("new session: agent=%s shadow=%v\n", agentID, agentCfg.ShadowMode)
	return s
}

func cleanupSessions() {
	for {
		time.Sleep(5 * time.Minute)
		sessionsMu.Lock()
		before := len(sessions)
		for id, s := range sessions {
			if time.Since(s.LastSeen) > 24*time.Hour {
				delete(sessions, id)
			}
		}
		after := len(sessions)
		sessionsMu.Unlock()
		if before != after {
			fmt.Printf("cleaned up %d stale sessions, %d active\n", before-after, after)
		}
	}
}

type DetectionResult struct {
	Triggered  bool
	Reason     string
	Layer      string
	ShadowMode bool
	ConfigHash string
}

// ProcessRequest runs detection. returns immediately on first hit.
// Advanced layers (jitter, sequence, semantic) are Pro/Enterprise.
// nakshguard.dev/pro
func (s *AgentSession) ProcessRequest(tokens int, prompt string) DetectionResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LastSeen = time.Now()

	// refresh config if a proxy.yaml is loaded. skipped in tests where
	// GetConfig() returns nil and we want the manually set config to stick.
	if GetConfig() != nil {
		s.Config, s.ConfigHash = GetAgentConfig(s.AgentID)
	}

	if !s.RateLimiter.Allow() {
		return s.fired("rate_limit: too many requests too fast", "rate_limit")
	}

	if s.TotalTokens+tokens > s.Config.Limits.HardTokenLimit {
		return s.fired(
			fmt.Sprintf("hard_limit: at %d tokens, +%d would exceed %d",
				s.TotalTokens, tokens, s.Config.Limits.HardTokenLimit),
			"hard_limit",
		)
	}

	// flat repeats have zero token growth so CVE misses them entirely
	if fired, reason := s.checkRepetition(prompt); fired {
		return s.fired(reason, "repetition")
	}

	if fired, reason := s.checkVelocity(tokens); fired {
		return s.fired(reason, "cve")
	}

	// commit the pessimistic estimate. output tokens are added separately
	// when the response lands — keeps parallel requests from corrupting each other.
	s.TotalTokens += tokens
	s.RequestCount++
	s.LastRequestTime = time.Now()

	return DetectionResult{ShadowMode: s.Config.ShadowMode, ConfigHash: s.ConfigHash}
}

func (s *AgentSession) UpdateWithRealTokens(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if n <= 0 {
		return
	}
	s.TotalTokens += n
}

func (s *AgentSession) OverHardLimit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.TotalTokens > s.Config.Limits.HardTokenLimit
}

func (s *AgentSession) InShadowMode() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Config.ShadowMode
}

// RollbackEstimate: upstream failed, request cost nothing, don't charge for it.
func (s *AgentSession) RollbackEstimate(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if n <= 0 {
		return
	}
	s.TotalTokens -= n
	if s.TotalTokens < 0 {
		s.TotalTokens = 0
	}
	fmt.Printf("[token rollback] agent=%s -%d total=%d\n",
		s.AgentID, n, s.TotalTokens)
}

func (s *AgentSession) checkVelocity(n int) (bool, string) {
	cfg := s.Config.Limits.ContextVelocity
	now := time.Now()

	s.tokenSamples = append(s.tokenSamples, TokenSample{n, now})
	if len(s.tokenSamples) > 20 {
		copy(s.tokenSamples, s.tokenSamples[len(s.tokenSamples)-20:]) // not [1:] — that pins the backing array
		s.tokenSamples = s.tokenSamples[:20]
	}

	if cfg.Mode == "growth_rate" {
		if len(s.tokenSamples) < cfg.MinSamples {
			return false, ""
		}
		growing := 0
		for i := 1; i < len(s.tokenSamples); i++ {
			if s.tokenSamples[i].tokens > s.tokenSamples[i-1].tokens {
				growing++
			}
		}
		rate := float64(growing) / float64(len(s.tokenSamples)-1)
		if rate > cfg.MaxGrowthRate {
			return true, fmt.Sprintf("cve(growth_rate): %.0f%% growing (limit %.0f%%)",
				rate*100, cfg.MaxGrowthRate*100)
		}
		return false, ""
	}

	elapsed := time.Since(s.window.start).Seconds()
	if elapsed >= cfg.WindowSeconds {
		s.window.tokens = 0
		s.window.start = now
	}
	// check first, commit after — blocked requests shouldn't inflate the window
	if s.window.tokens+n > cfg.MaxTokensPerWindow {
		return true, fmt.Sprintf("cve(absolute): %d+%d tokens exceeds %d in %.0fs window",
			s.window.tokens, n, cfg.MaxTokensPerWindow, elapsed)
	}
	s.window.tokens += n
	return false, ""
}

// checkRepetition hashes the prompt and counts duplicates in the window.
func (s *AgentSession) checkRepetition(prompt string) (bool, string) {
	cfg := s.Config.Limits.Repetition
	if cfg.MaxRepeats <= 0 {
		return false, ""
	}

	now := time.Now()
	h := sha256.New()
	h.Write([]byte(prompt))
	hash := hex.EncodeToString(h.Sum(nil))

	win := cfg.WindowSeconds
	if win <= 0 {
		win = 60
	}
	cutoff := now.Add(-time.Duration(win * float64(time.Second)))

	count := 0
	for _, r := range s.recentHashes {
		if r.hash == hash && r.at.After(cutoff) {
			count++
		}
	}

	s.recentHashes = append(s.recentHashes, struct {
		hash string
		at   time.Time
	}{hash, now})

	if len(s.recentHashes) > 100 { // same copy+truncate as tokenSamples
		copy(s.recentHashes, s.recentHashes[len(s.recentHashes)-100:])
		s.recentHashes = s.recentHashes[:100]
	}

	if count >= cfg.MaxRepeats {
		return true, fmt.Sprintf(
			"repetition: identical request %d times in %.0fs (limit %d)",
			count, win, cfg.MaxRepeats)
	}
	return false, ""
}

func (s *AgentSession) fired(reason, layer string) DetectionResult {
	return DetectionResult{
		Triggered:  true,
		Reason:     reason,
		Layer:      layer,
		ShadowMode: s.Config.ShadowMode,
		ConfigHash: s.ConfigHash,
	}
}

// pessimistic by design: ~50% over. better to soft-limit early than miss a loop.
func pessimistic(n int) int {
	n = (n * 3) / 8
	if n < 1 {
		return 1
	}
	return n
}
