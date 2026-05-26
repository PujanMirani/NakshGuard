package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// shared transport - stdlib default is 2 idle conns/host which causes TCP
// churn when several agents fire at once
var sharedTransport = &http.Transport{
	MaxIdleConns:        200,
	MaxIdleConnsPerHost: 100,
	IdleConnTimeout:     90 * time.Second,
	ForceAttemptHTTP2:   true,
}

type openAIRequest struct {
	Stream   bool `json:"stream"`
	Messages []struct {
		Role string `json:"role"`
		// string for text, array of parts for vision. RawMessage handles both.
		Content json.RawMessage `json:"content"`
	} `json:"messages"`

	// /v1/embeddings sends "input" instead of "messages"
	Input json.RawMessage `json:"input"`
}

type apiUsage struct {
	Usage struct {
		Total      int `json:"total_tokens"`
		Completion int `json:"completion_tokens"`
	} `json:"usage"`
}

func extractPrompt(body []byte) (string, int, bool) {
	var req openAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// fall back to whole-body rune count if we can't parse it
		return string(body), pessimistic(len([]rune(string(body)))), false
	}

	last := "" // hashed for repeat detection
	if len(req.Messages) > 0 {
		last = contentToText(req.Messages[len(req.Messages)-1].Content)
	}

	// whole conversation cost - it all gets re-sent every turn.
	// runes not bytes: a Hindi or CJK char is 3-4 bytes, len() lies.
	n := 0
	for _, m := range req.Messages {
		n += contentSize(m.Content) + len([]rune(m.Role)) + 4
	}

	if len(req.Messages) == 0 && len(req.Input) > 0 { // embeddings path
		text := contentToText(req.Input)
		if text == "" {
			n = contentSize(req.Input)
		} else {
			n = len([]rune(text))
			last = text
		}
	}

	return last, pessimistic(n), req.Stream
}

func contentToText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		out := ""
		for _, p := range parts {
			if p.Text != "" {
				out += p.Text + " "
			}
		}
		return out
	}
	return ""
}

// contentSize: char cost of a content field. images are capped flat -
// their base64 size is not their token cost.
func contentSize(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return len([]rune(s))
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		total := 0
		for _, p := range parts {
			if p.Text != "" {
				total += len([]rune(p.Text))
			} else {
				total += 3000 // ~750 tokens per image, what providers roughly charge
			}
		}
		return total
	}
	return 0
}

// extractRealTokens pulls completion_tokens from the response. input was
// already counted at request time, so only output gets added here.
func extractRealTokens(body []byte) int {
	var r apiUsage
	if err := json.Unmarshal(body, &r); err != nil {
		return 0
	}
	if r.Usage.Completion > 0 {
		return r.Usage.Completion
	}
	return 0
}

func proxyAuthKey() string {
	if k := os.Getenv("NAKSHGUARD_AUTH_KEY"); k != "" {
		return k
	}
	return os.Getenv("FIREBREAK_AUTH_KEY")
}

func handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions { // answer preflights, don't forward them
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Agent-ID, X-NakshGuard-Auth")
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// NAKSHGUARD_AUTH_KEY: anyone on the network who finds port 8080 can
	// use your API key without it. leave unset on isolated hosts.
	if key := proxyAuthKey(); key != "" {
		if r.Header.Get("X-NakshGuard-Auth") != key {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized","hint":"set X-NakshGuard-Auth header"}`)
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB, generous
	defer r.Body.Close()                            // before anything that might return
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if strings.Contains(err.Error(), "http: request body too large") {
			http.Error(w, `{"error":"request too large (10MB limit)"}`,
				http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"could not read body"}`, http.StatusBadRequest)
		return
	}

	agentID := r.Header.Get("X-Agent-ID")
	if agentID == "" {
		agentID = "default"
	}

	prompt, est, streaming := extractPrompt(body)
	session := getOrCreateSession(agentID)
	result := session.ProcessRequest(est, prompt)

	if result.Triggered {
		logEvent(session, result)
		if !result.ShadowMode {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-NakshGuard-Layer", result.Layer)
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w,
				`{"error":"circuit_breaker_triggered","reason":"%s","layer":"%s","agent":"%s"}`,
				result.Reason, result.Layer, agentID)
			return
		}
		fmt.Printf("[shadow] agent=%s would have been blocked: %s\n",
			agentID, result.Reason)
	}

	r.Body = io.NopCloser(bytes.NewBuffer(body)) // ReadAll consumed it
	r.ContentLength = int64(len(body))

	target := GetConfig().GlobalSettings.LLMTarget
	if target == "" {
		target = "https://api.openai.com"
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		http.Error(w, `{"error":"bad llm_target in config"}`,
			http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = sharedTransport
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host

		host := strings.ToLower(targetURL.Host)
		anthropic := strings.Contains(host, "anthropic")

		// normalize the path per provider
		if req.URL.Path == "" || req.URL.Path == "/" || req.URL.Path == "/api/chat" {
			if anthropic {
				req.URL.Path = "/v1/messages"
			} else {
				req.URL.Path = "/v1/chat/completions"
			}
		}

		req.Header.Set("Content-Type", "application/json")

		req.Header.Del("Accept-Encoding") // no gzip or we json-parse zip bytes

		if anthropic {
			// anthropic uses x-api-key, not Bearer. sending Bearer = 401.
			key := os.Getenv("ANTHROPIC_API_KEY")
			if key == "" {
				key = os.Getenv("OPENAI_API_KEY")
			}
			if key != "" {
				req.Header.Set("x-api-key", key)
			}
			if req.Header.Get("anthropic-version") == "" {
				req.Header.Set("anthropic-version", "2023-06-01")
			}
			req.Header.Del("Authorization")
		} else {
			key := os.Getenv("OPENAI_API_KEY") // also covers groq, ollama, litellm
			if key == "" {
				key = os.Getenv("ANTHROPIC_API_KEY")
			}
			if key != "" {
				req.Header.Set("Authorization", "Bearer "+key)
			}
		}
	}

	// fail open. also refund the estimate - a run of upstream 500s
	// shouldn't look like a loop and trip the hard limit.
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		fmt.Printf("upstream error for agent=%s: %v\n", agentID, err)
		session.RollbackEstimate(est)
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusBadGateway)
	}

	fmt.Printf("-> agent=%s est~%d total=%d streaming=%v\n",
		agentID, est, session.TotalTokens, streaming)

	if streaming {
		sw := &streamCounter{ResponseWriter: w, session: session, statusCode: 200}
		proxy.ServeHTTP(sw, r)
		if r.Context().Err() != nil { // client cancelled, refund estimate
			session.RollbackEstimate(est)
		} else {
			sw.finalize()
		}
		return
	}

	ti := &tokenInterceptor{ResponseWriter: w, session: session, statusCode: 200}
	proxy.ServeHTTP(ti, r)
	switch {
	case r.Context().Err() != nil:
		session.RollbackEstimate(est) // client cancelled
	case ti.statusCode >= 400:
		session.RollbackEstimate(est) // upstream error, request cost nothing
	default:
		ti.finalize()
	}
}

// streamCounter tallies a streaming response as it flows, not after. a stream
// that rambles for a minute would otherwise burn the budget invisibly - so we
// credit tokens every 32KB and can cut it mid-flight if it blows the limit.
type streamCounter struct {
	http.ResponseWriter
	session    *AgentSession
	statusCode int
	bytes      int
	buf        bytes.Buffer // capped copy of the stream
	credited   int          // tokens already added to the session mid-stream
	lastScan   int          // buf length at the last incremental scan
	cut        bool
}

const streamBufCap = 2 << 20 // stop buffering past 2MB (still forwards)
const scanEvery = 32 << 10   // re-count output tokens every 32KB

var errStreamCut = fmt.Errorf("nakshguard: hard token limit exceeded mid-stream")

func (sc *streamCounter) WriteHeader(code int) {
	sc.statusCode = code
	sc.ResponseWriter.WriteHeader(code)
}

func (sc *streamCounter) Write(b []byte) (int, error) {
	if sc.cut {
		return 0, errStreamCut
	}
	sc.bytes += len(b)
	if sc.buf.Len() < streamBufCap {
		sc.buf.Write(b)
	}

	// every 32KB, credit what's been produced so far and re-check the limit
	if sc.buf.Len()-sc.lastScan >= scanEvery {
		sc.lastScan = sc.buf.Len()
		chars := countDeltaChars(sc.buf.Bytes())
		if add := chars/4 - sc.credited; add > 0 {
			sc.session.UpdateWithRealTokens(add)
			sc.credited += add
		}
		// cut a runaway stream here - there's no "next request" to block it
		if !sc.session.InShadowMode() && sc.session.OverHardLimit() {
			sc.cut = true
			fmt.Printf("[cut mid-stream] agent=%s over hard limit\n", sc.session.AgentID)
			return 0, errStreamCut
		}
	}

	n, err := sc.ResponseWriter.Write(b)
	if f, ok := sc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

func (sc *streamCounter) finalize() {
	if sc.statusCode >= 400 || sc.bytes == 0 {
		return
	}
	raw := sc.buf.Bytes()

	// real usage in the closing chunk? correct whatever we credited mid-stream.
	// openai: stream_options include_usage. anthropic: always sent.
	real := lastUsageNumber(raw, `"completion_tokens":`)
	if real == 0 {
		real = lastUsageNumber(raw, `"output_tokens":`)
	}
	if real > 0 {
		if diff := real - sc.credited; diff > 0 {
			sc.session.UpdateWithRealTokens(diff)
		} else if diff < 0 {
			sc.session.RollbackEstimate(-diff)
		}
		return
	}

	if chars := countDeltaChars(raw); chars > 0 { // settle from deltas, not raw bytes
		if add := chars/4 - sc.credited; add > 0 {
			sc.session.UpdateWithRealTokens(add)
		}
		return
	}

	if sc.credited == 0 { // unknown format, rough byte guess beats nothing
		sc.session.UpdateWithRealTokens(sc.bytes / 4)
	}
}

// lastUsageNumber finds the last occurrence of key and returns the int after it.
// last not first: usage is in the final chunk; earlier occurrences are zero.
func lastUsageNumber(raw []byte, key string) int {
	i := bytes.LastIndex(raw, []byte(key))
	if i < 0 {
		return 0
	}
	i += len(key)
	for i < len(raw) && raw[i] == ' ' {
		i++
	}
	n := 0
	for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
		n = n*10 + int(raw[i]-'0')
		i++
	}
	return n
}

// countDeltaChars: sum the actual model output from stream deltas, not the
// json envelope around each chunk.
func countDeltaChars(raw []byte) int {
	total := 0
	for _, key := range []string{`"content":"`, `"text":"`} {
		k := []byte(key)
		pos := 0
		for {
			i := bytes.Index(raw[pos:], k)
			if i < 0 {
				break
			}
			i += pos + len(k)
			j := i
			for j < len(raw) {
				if raw[j] == '\\' { // escaped char, skip both
					j += 2
					continue
				}
				if raw[j] == '"' {
					break
				}
				j++
			}
			if j > len(raw) {
				j = len(raw)
			}
			total += len([]rune(string(raw[i:j])))
			pos = j
		}
	}
	return total
}

// tokenInterceptor buffers the response body to read usage from it once done.
type tokenInterceptor struct {
	http.ResponseWriter
	session    *AgentSession
	statusCode int
	buf        bytes.Buffer
}

func (t *tokenInterceptor) WriteHeader(code int) {
	t.statusCode = code
	t.ResponseWriter.WriteHeader(code)
}

func (t *tokenInterceptor) Write(b []byte) (int, error) {
	t.buf.Write(b) // buffer only; finalize() parses once at the end
	return t.ResponseWriter.Write(b)
}

func (t *tokenInterceptor) finalize() {
	if t.statusCode >= 400 {
		return // caller already rolled the estimate back
	}
	if real := extractRealTokens(t.buf.Bytes()); real > 0 {
		t.session.UpdateWithRealTokens(real)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	sessionsMu.Lock()
	n := len(sessions)
	sessionsMu.Unlock()

	cfg := GetConfig()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w,
		`{"ok":true,"version":"%s","tier":"%s","sessions":%d,"config_hash":"%s","shadow":%v}`,
		ProxyVersion, cfg.Tier, n, cfg.configHash, cfg.GlobalSettings.ShadowMode)
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	type row struct {
		Agent  string `json:"agent"`
		Tokens int    `json:"tokens"`
		Reqs   int    `json:"requests"`
		Shadow bool   `json:"shadow"`
	}

	rows := make([]row, 0, len(sessions))
	for _, s := range sessions {
		rows = append(rows, row{s.AgentID, s.TotalTokens, s.RequestCount, s.Config.ShadowMode})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows)
}
