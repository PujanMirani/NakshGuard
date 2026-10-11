package main

import (
	"testing"
)

// these tests check the detection logic directly, without HTTP.
// run them with:  go test -v
// run with race detector:  go test -race -v

func testConfig() AgentConfig {
	return AgentConfig{
		ShadowMode: false,
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

func newTestSession() *AgentSession {
	return &AgentSession{
		AgentID:     "test",
		Config:      testConfig(),
		RateLimiter: NewRateLimiter(100, 10), // high limit so it doesn't interfere
	}
}

// a growing conversation should eventually trigger CVE
func TestGrowthLoopIsCaught(t *testing.T) {
	s := newTestSession()
	caught := false

	for i := 1; i <= 15; i++ {
		// each request bigger than the last
		tokens := i * 100
		result := s.ProcessRequest(tokens, "prompt")
		if result.Triggered {
			caught = true
			t.Logf("growth loop caught at turn %d, layer=%s", i, result.Layer)
			break
		}
	}

	if !caught {
		t.Error("growth loop was NOT caught - CVE failed")
	}
}

// the identical request repeated should trigger repetition
func TestRepeatLoopIsCaught(t *testing.T) {
	s := newTestSession()
	caught := false

	for i := 1; i <= 15; i++ {
		// same request every time, same size
		result := s.ProcessRequest(100, "identical prompt every time")
		if result.Triggered {
			caught = true
			t.Logf("repeat loop caught at turn %d, layer=%s", i, result.Layer)
			break
		}
	}

	if !caught {
		t.Error("repeat loop was NOT caught - repetition detection failed")
	}
}

// a normal varied conversation should NOT trigger anything (no false positives)
func TestNormalTrafficNotBlocked(t *testing.T) {
	s := newTestSession()

	// varied, non-growing, non-repeating requests
	prompts := []string{
		"what is the weather today",
		"explain quantum computing briefly",
		"write a haiku about spring",
		"what is 2 plus 2",
		"summarize the news",
		"how do I cook pasta",
	}

	for i, p := range prompts {
		// roughly constant size, different content
		result := s.ProcessRequest(150, p)
		if result.Triggered {
			t.Errorf("FALSE POSITIVE: normal request %d blocked by %s: %s",
				i+1, result.Layer, result.Reason)
		}
	}
}

// hitting the hard token limit should fire
func TestHardLimitIsCaught(t *testing.T) {
	s := newTestSession()
	s.Config.Limits.HardTokenLimit = 1000

	result := s.ProcessRequest(2000, "huge request") // over the limit immediately
	if !result.Triggered || result.Layer != "hard_limit" {
		t.Errorf("hard limit not caught, got triggered=%v layer=%s",
			result.Triggered, result.Layer)
	}
}

// rate limiter should fire when too many requests come fast
func TestRateLimitIsCaught(t *testing.T) {
	s := newTestSession()
	s.RateLimiter = NewRateLimiter(5, 10) // only 5 allowed

	caught := false
	for i := 1; i <= 10; i++ {
		// vary the prompt so repetition/cve don't fire first
		result := s.ProcessRequest(100, string(rune('a'+i)))
		if result.Triggered && result.Layer == "rate_limit" {
			caught = true
			break
		}
	}

	if !caught {
		t.Error("rate limit was not caught")
	}
}

// empty prompt should not crash
func TestEmptyPromptDoesNotCrash(t *testing.T) {
	s := newTestSession()
	// should not panic
	s.ProcessRequest(0, "")
	s.ProcessRequest(1, "")
}

// concurrent requests to the same session should not race or crash
// run this with: go test -race -run TestConcurrent
func TestConcurrentRequests(t *testing.T) {
	s := newTestSession()
	s.RateLimiter = NewRateLimiter(10000, 10)

	done := make(chan bool)
	for i := 0; i < 50; i++ {
		go func(n int) {
			s.ProcessRequest(100, "concurrent test")
			done <- true
		}(i)
	}

	for i := 0; i < 50; i++ {
		<-done
	}
	// if -race is on and there's a locking bug, the test fails here
}
