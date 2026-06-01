package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// logEvent prints a detection event as JSON to stdout.
// Pro adds OTel to Datadog, Grafana, etc. nakshguard.dev/pro
func logEvent(s *AgentSession, result DetectionResult) {
	age := time.Since(s.StartTime).Seconds()
	tpm := 0
	if age > 0 {
		tpm = int(float64(s.TotalTokens) / age * 60)
	}

	event := map[string]interface{}{
		"event":           "circuit_breaker_triggered",
		"ts":              time.Now().UTC().Format(time.RFC3339),
		"version":         ProxyVersion,
		"agent_id":        s.AgentID,
		"violation_layer": result.Layer,
		"reason":          result.Reason,
		"shadow_mode":     result.ShadowMode,
		"action":          map[bool]string{true: "shadow_only", false: "HTTP_429"}[result.ShadowMode],
		"session": map[string]interface{}{
			"total_tokens":   s.TotalTokens,
			"request_count":  s.RequestCount,
			"age_seconds":    age,
			"tokens_per_min": tpm,
		},
	}

	out, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		fmt.Printf("warn: couldn't marshal event: %v\n", err)
		return
	}

	if result.ShadowMode {
		fmt.Printf("[shadow - would have blocked]\n%s\n", out)
	} else {
		fmt.Printf("[blocked]\n%s\n", out)
	}
}
