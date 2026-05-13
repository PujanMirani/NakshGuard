package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const TierV1 = "v1"

type RateLimiterConfig struct {
	MaxRequests   int
	WindowSeconds float64
}

// CVEConfig: two modes.
//
//	growth_rate: fires when tokens grow consistently across recent requests
//	absolute:    fires when tokens exceed a cap within a time window
type CVEConfig struct {
	Mode               string
	MaxGrowthRate      float64
	MinSamples         int
	MaxTokensPerWindow int
	WindowSeconds      float64
}

type RepetitionConfig struct {
	MaxRepeats    int
	WindowSeconds float64
}

// LimitsConfig: per-agent thresholds. V1 has rate limit, hard limit, CVE,
// and basic repetition. jitter/sequence/semantic/cycle detection are Pro.
type LimitsConfig struct {
	HardTokenLimit  int
	ContextVelocity CVEConfig
	Repetition      RepetitionConfig
}

type AgentConfig struct {
	ShadowMode bool
	Limits     LimitsConfig
}

type GlobalSettings struct {
	ShadowMode  bool
	LLMTarget   string
	RateLimiter RateLimiterConfig
}

type ProxyConfig struct {
	Tier           string
	GlobalSettings GlobalSettings
	DefaultLimits  LimitsConfig
	Agents         map[string]AgentConfig
	configHash     string
}

var (
	currentConfig *ProxyConfig
	configMu      sync.RWMutex
	configPath    = "proxy.yaml"
)

func GetConfig() *ProxyConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	return currentConfig
}

func GetTier() string {
	cfg := GetConfig()
	if cfg == nil {
		return TierV1
	}
	return cfg.Tier
}

func GetAgentConfig(agentID string) (AgentConfig, string) {
	cfg := GetConfig()
	if cfg == nil {
		return defaultAgentConfig(), ""
	}
	if agent, ok := cfg.Agents[agentID]; ok {
		return mergeWithDefaults(agent, cfg.DefaultLimits), cfg.configHash
	}
	return AgentConfig{
		ShadowMode: cfg.GlobalSettings.ShadowMode,
		Limits:     cfg.DefaultLimits,
	}, cfg.configHash
}

func defaultAgentConfig() AgentConfig {
	return AgentConfig{
		ShadowMode: true,
		Limits: LimitsConfig{
			HardTokenLimit: 100000,
			ContextVelocity: CVEConfig{
				Mode:          "growth_rate",
				MaxGrowthRate: 0.8,
				MinSamples:    5,
			},
			Repetition: RepetitionConfig{
				MaxRepeats:    5,
				WindowSeconds: 60,
			},
		},
	}
}

func mergeWithDefaults(a AgentConfig, d LimitsConfig) AgentConfig {
	if a.Limits.HardTokenLimit == 0 {
		a.Limits.HardTokenLimit = d.HardTokenLimit
	}
	if a.Limits.ContextVelocity.Mode == "" {
		a.Limits.ContextVelocity = d.ContextVelocity
	}
	if a.Limits.Repetition.MaxRepeats == 0 {
		a.Limits.Repetition = d.Repetition
	}
	return a
}

// watchConfigReload: SIGHUP reloads proxy.yaml, no restart needed.
func watchConfigReload() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		fmt.Println("received SIGHUP, reloading config...")
		cfg, err := loadConfig(configPath)
		if err != nil {
			fmt.Printf("warn: config reload failed: %v (keeping current config)\n", err)
			continue
		}
		configMu.Lock()
		currentConfig = cfg
		configMu.Unlock()
		fmt.Printf("config reloaded: hash=%s\n", cfg.configHash)
	}
}

func loadConfig(path string) (*ProxyConfig, error) {
	// one read, not two. two reads (os.Open + os.ReadFile) open a window
	// where the file can change between them, making hash and rules disagree.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	h := sha256.New()
	h.Write(raw)
	hash := hex.EncodeToString(h.Sum(nil))[:8]

	cfg := &ProxyConfig{
		Tier: TierV1,
		GlobalSettings: GlobalSettings{
			ShadowMode: true,
			LLMTarget:  "https://api.openai.com",
			RateLimiter: RateLimiterConfig{
				MaxRequests:   20,
				WindowSeconds: 10,
			},
		},
		DefaultLimits: LimitsConfig{
			HardTokenLimit: 100000,
			ContextVelocity: CVEConfig{
				Mode:          "growth_rate",
				MaxGrowthRate: 0.8,
				MinSamples:    5,
			},
			Repetition: RepetitionConfig{
				MaxRepeats:    5,
				WindowSeconds: 60,
			},
		},
		Agents:     make(map[string]AgentConfig),
		configHash: hash,
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	var (
		currentAgent    string
		inAgents        bool
		inGlobal        bool
		inLimits        bool
		inRateLimiter   bool
		inCVE           bool
		inRepetition    bool
		inDefaultLimits bool
	)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))

		if indent == 0 {
			inAgents = false
			inGlobal = false
			inLimits = false
			inRateLimiter = false
			inCVE = false
			inRepetition = false
			inDefaultLimits = false
			currentAgent = ""

			switch {
			case strings.HasPrefix(trimmed, "global_settings:"):
				inGlobal = true
			case strings.HasPrefix(trimmed, "agents:"):
				inAgents = true
			case strings.HasPrefix(trimmed, "default_limits:"):
				inDefaultLimits = true
			}
			continue
		}

		kv := strings.SplitN(trimmed, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		// strip inline comments: `20 # note` → `20`. quoted values keep their #.
		if !strings.HasPrefix(val, `"`) {
			if i := strings.Index(val, "#"); i >= 0 {
				val = strings.TrimSpace(val[:i])
			}
		}

		if inGlobal && indent == 2 {
			switch key {
			case "shadow_mode":
				cfg.GlobalSettings.ShadowMode = val == "true"
			case "llm_target":
				cfg.GlobalSettings.LLMTarget = strings.Trim(val, `"`)
			case "rate_limiter":
				inRateLimiter = true
			}
			continue
		}

		if inGlobal && inRateLimiter && indent == 4 {
			switch key {
			case "max_requests":
				if n, err := strconv.Atoi(val); err == nil {
					cfg.GlobalSettings.RateLimiter.MaxRequests = n
				}
			case "window_seconds":
				if n, err := strconv.ParseFloat(val, 64); err == nil {
					cfg.GlobalSettings.RateLimiter.WindowSeconds = n
				}
			}
			continue
		}

		if inDefaultLimits && indent == 2 {
			switch key {
			case "hard_token_limit":
				if n, err := strconv.Atoi(val); err == nil {
					cfg.DefaultLimits.HardTokenLimit = n
				}
			case "context_velocity":
				inCVE = true
				inRepetition = false
			case "repetition":
				inRepetition = true
				inCVE = false
			}
			continue
		}

		if inDefaultLimits && inCVE && indent == 4 {
			parseCVE(&cfg.DefaultLimits.ContextVelocity, key, val)
			continue
		}

		if inDefaultLimits && inRepetition && indent == 4 {
			switch key {
			case "max_repeats":
				if n, err := strconv.Atoi(val); err == nil {
					cfg.DefaultLimits.Repetition.MaxRepeats = n
				}
			case "window_seconds":
				if n, err := strconv.ParseFloat(val, 64); err == nil {
					cfg.DefaultLimits.Repetition.WindowSeconds = n
				}
			}
			continue
		}

		// agents section
		if inAgents {
			if indent == 2 && strings.HasSuffix(trimmed, ":") {
				currentAgent = strings.TrimSuffix(strings.Trim(key, `"`), ":")
				cfg.Agents[currentAgent] = AgentConfig{
					ShadowMode: cfg.GlobalSettings.ShadowMode,
					Limits:     cfg.DefaultLimits,
				}
				inLimits = false
				inCVE = false
				continue
			}

			if currentAgent == "" {
				continue
			}

			agent := cfg.Agents[currentAgent]

			if indent == 4 {
				switch key {
				case "shadow_mode":
					agent.ShadowMode = val == "true"
				case "limits":
					inLimits = true
					inCVE = false
				}
			}

			if indent == 6 && inLimits {
				switch key {
				case "hard_token_limit":
					if n, err := strconv.Atoi(val); err == nil {
						agent.Limits.HardTokenLimit = n
					}
				case "context_velocity":
					inCVE = true
				}
			}

			if indent == 8 && inCVE {
				parseCVE(&agent.Limits.ContextVelocity, key, val)
			}

			cfg.Agents[currentAgent] = agent
		}
	}

	return cfg, scanner.Err()
}

func parseCVE(cve *CVEConfig, key, val string) {
	switch key {
	case "mode":
		cve.Mode = strings.Trim(val, `"`)
	case "max_growth_rate":
		if n, err := strconv.ParseFloat(val, 64); err == nil {
			cve.MaxGrowthRate = n
		}
	case "min_samples":
		if n, err := strconv.Atoi(val); err == nil {
			cve.MinSamples = n
		}
	case "max_tokens_per_window":
		if n, err := strconv.Atoi(val); err == nil {
			cve.MaxTokensPerWindow = n
		}
	case "window_seconds":
		if n, err := strconv.ParseFloat(val, 64); err == nil {
			cve.WindowSeconds = n
		}
	}
}
