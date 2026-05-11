package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

// bump this when shipping a new release
const ProxyVersion = "0.4.0"

func main() {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't load proxy.yaml: %v\n", err)
		fmt.Fprintf(os.Stderr, "make sure proxy.yaml is in the same directory\n")
		os.Exit(1)
	}

	configMu.Lock()
	currentConfig = cfg
	configMu.Unlock()

	if os.Getenv("OPENAI_API_KEY") == "" && os.Getenv("ANTHROPIC_API_KEY") == "" {
		fmt.Println("warn: no api key set, forwarding will fail")
		fmt.Println("      set OPENAI_API_KEY or ANTHROPIC_API_KEY in your environment")
	}

	fmt.Printf("nakshguard %s | tier=%s shadow=%v\n",
		ProxyVersion, cfg.Tier, cfg.GlobalSettings.ShadowMode)
	fmt.Printf("target: %s | config: %s\n",
		cfg.GlobalSettings.LLMTarget, cfg.configHash)
	fmt.Println("---")
	fmt.Println("  POST /api/chat  — proxy endpoint")
	fmt.Println("  GET  /health    — health check")
	fmt.Println("  GET  /stats     — session stats")
	fmt.Println("---")
	fmt.Println("reload config without restart: kill -HUP <pid>")
	fmt.Println("listening on :8080")

	go cleanupSessions()
	go watchConfigReload()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/chat", handleTraffic)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/stats", handleStats)

	// real timeouts, or one slow client can hold connections open forever.
	// write timeout is long on purpose - streaming responses take a while.
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server died: %v\n", err)
		os.Exit(1)
	}
}
