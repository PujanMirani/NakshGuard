package main

import (
	"sync"
	"time"
)

// sliding window rate limiter. first check in the cascade, before any
// token math, so it fires even if token counting has no data yet.
type SlidingWindowRateLimiter struct {
	mu         sync.Mutex
	timestamps []time.Time
	max        int
	windowSec  float64
}

func NewRateLimiter(max int, windowSec float64) *SlidingWindowRateLimiter {
	return &SlidingWindowRateLimiter{max: max, windowSec: windowSec}
}

func (rl *SlidingWindowRateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Duration(rl.windowSec * float64(time.Second)))

	// reuse the slice, avoid alloc
	valid := rl.timestamps[:0]
	for _, t := range rl.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	rl.timestamps = valid

	if len(rl.timestamps) >= rl.max {
		return false
	}

	rl.timestamps = append(rl.timestamps, now)
	return true
}

func (rl *SlidingWindowRateLimiter) Count() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.timestamps)
}
