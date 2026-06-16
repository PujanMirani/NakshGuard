# nakshguard

A reverse proxy that detects and blocks runaway loops in AI agent traffic
before they consume excessive API tokens.

NakshGuard sits between your agents and the LLM API. It inspects each request,
tracks per-agent session state, and applies a set of detection layers to
identify looping behaviour — rapid repetition, unbounded context growth, and
rate spikes — then blocks or logs them according to your configuration. It runs
on-premises with no external dependencies; request data never leaves your
network.

```
nakshguard 0.4.0 | tier=v1 shadow=false
target: https://api.openai.com | listening on :8080
```

## Features

- Reverse proxy for the OpenAI and Anthropic chat APIs (auto-detected)
- Four detection layers: rate limit, hard token limit, repetition, context velocity
- Per-agent session tracking and configurable thresholds
- Shadow mode for safe calibration before enforcement
- Fail-open: if the proxy fails, traffic passes through to the upstream
- Sub-millisecond overhead, in-memory state, zero external dependencies
- Hot config reload via SIGHUP

## Install

```bash
go build .
```

Or with Docker:

```bash
docker build -t nakshguard .
docker run -p 8080:8080 -e OPENAI_API_KEY=sk-... nakshguard
```

## Usage

Run the proxy:

```bash
OPENAI_API_KEY=sk-... ./nakshguard
```

Point your client at the proxy and identify each agent with a header:

```python
client = openai.OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url="http://localhost:8080",
    default_headers={"X-Agent-ID": "billing_bot"},
)
```

Requests now flow through NakshGuard. It estimates request cost, runs the
detection layers, and forwards to the upstream or blocks with HTTP 429.

## Detection layers

| layer      | triggers on |
|------------|-------------|
| rate limit | too many requests in a short window |
| hard limit | session token total exceeds a ceiling |
| repetition | identical requests repeated within the window |
| cve        | context size growing across consecutive requests |

Context velocity (cve) detects the common error-append loop, where an agent
appends its last error to the context and retries, growing the request each
turn. Additional detection layers are available in the Pro and Enterprise
tiers; see [COMMERCIAL.md](COMMERCIAL.md).

## Shadow mode

By default the proxy starts in shadow mode: every layer runs and logs what it
would have blocked, without blocking anything. Run it against real traffic,
review the logs, then disable shadow mode in `proxy.yaml`:

```yaml
global_settings:
  shadow_mode: false
```

Reload without restarting:

```bash
kill -HUP $(pgrep nakshguard)
```

Blocking can also be enabled per agent for incremental rollout.

## Configuration

All settings live in `proxy.yaml`: the upstream target, rate limits, and
per-agent thresholds. The most common change is `llm_target` to match your
provider.

> If the host is reachable by untrusted clients, set `NAKSHGUARD_AUTH_KEY` so
> that only requests carrying the matching `X-Nakshguard-Auth` header are
> accepted. Without it, anyone who can reach the port can use your upstream
> credentials.

## Endpoints

| path      | purpose |
|-----------|---------|
| `/v1/...` | proxied to the upstream LLM API |
| `/health` | liveness and current mode |
| `/stats`  | per-agent session counters |

## Testing

```bash
go test -race -v             # unit tests
python3 tests/run_all_tests.py   # integration tests (needs shadow_mode: false)
```

## Scaling

One instance tracks hundreds of agents in memory. To run multiple instances
behind a load balancer, route by `X-Agent-ID` so each agent maps to a
consistent instance. Shared-state clustering is on the roadmap.

## License

AGPL-3.0. Free for internal use with no source-sharing obligation. Commercial
licensing and the Pro/Enterprise detection layers are covered in
[COMMERCIAL.md](COMMERCIAL.md).
