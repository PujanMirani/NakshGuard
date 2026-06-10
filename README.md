# NakshGuard\

Stop runaway AI agent loops before they drain your API budget.

NakshGuard is a small reverse proxy that sits between your agents and the LLM
API. It watches how each agent behaves and cuts off the runaway patterns —
the error-retry spirals, the identical-request loops, the conversations that
grow without bound — before they show up on your invoice. It runs inside your
own network. Your prompts never leave your infrastructure.

```
nakshguard 0.4.0 | tier=v1 shadow=true
target: https://api.openai.com | listening on :8080

[shadow - would have blocked]
agent=billing_bot layer=cve
reason="91% of recent requests growing in size"
```

## why this exists

A LangChain agent looped for 11 days and ran up a $47K bill before anyone
noticed. That story isn't rare — it's the default failure mode of autonomous
agents. They get stuck, they retry, and because every request looks like
normal HTTP traffic, nothing flags it until the bill arrives.

The usual answers are `max_iterations` and a budget cap in the provider
dashboard. Both are blunt. A hard cap can't tell a productive agent from a
stuck one — it kills the job at step 99 of 100 and you lose the work *and* the
money. An iteration limit treats "the agent is making progress" and "the agent
is hitting the same wall 50 times" as the same thing.

NakshGuard looks at *behaviour* instead. Different failure modes get different
responses, and you get a chance to catch the loop while it's happening rather
than reading about it in next month's invoice.

## how it works

Point your agent's base URL at the proxy and add a header to identify it:

```python
client = openai.OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url="http://localhost:8080",        # was api.openai.com
    default_headers={"X-Agent-ID": "billing_bot"},
)
```

Every request now flows through NakshGuard. It estimates the request cost,
checks it against a few detection layers, and either forwards it to the LLM or
blocks it. If the proxy ever crashes it fails open — your agents fall through
to the API directly and keep working. It is never the reason your production
goes down.

It speaks the OpenAI API by default and switches to Anthropic's format
automatically when you point it at an Anthropic endpoint.

## detection layers (v1)

| layer        | catches |
|--------------|---------|
| rate limit   | too many requests in a short window |
| hard limit   | total session tokens over a ceiling |
| repetition   | the identical request sent over and over |
| cve          | the conversation growing without bound (the classic error-append loop) |

Context velocity (cve) is the important one. A looping agent keeps appending
its last error to the context and retrying, so each request is bigger than the
last. NakshGuard watches that growth pattern across recent requests and fires
when most of them are trending up.

Advanced layers — rephrase/jitter detection, tool-sequence cycles,
cross-agent loop detection, idempotency, and semantic matching — are part of
the Pro and Enterprise tiers. See [COMMERCIAL.md](COMMERCIAL.md).

## quick start

```bash
# build it
go build .

# run it (shadow mode is on by default — it logs, doesn't block)
OPENAI_API_KEY=sk-... ./nakshguard
```

Or with Docker:

```bash
docker build -t nakshguard .
docker run -p 8080:8080 -e OPENAI_API_KEY=sk-... nakshguard
```

Then point an agent at `http://localhost:8080` as shown above.

## shadow mode

NakshGuard starts in shadow mode. It runs every detection layer and logs what it
*would* have blocked, without actually blocking anything. Run it against your
real traffic for a couple of days, review the log, and confirm it's only
flagging real problems.

When you're ready, flip it in `proxy.yaml`:

```yaml
global_settings:
  shadow_mode: false
```

Reload without restarting:

```bash
kill -HUP $(pgrep nakshguard)
```

You can also turn blocking on per-agent, so you can roll it out one agent at a
time instead of all at once.

## configuration

Everything lives in `proxy.yaml` — the upstream target, the rate limit, the
per-agent thresholds. It's commented. The defaults are sensible; the one thing
you'll likely change is `llm_target` to match your provider.

## testing

```bash
go test -race -v        # unit tests for the detection logic

# integration tests (need the proxy running with shadow_mode: false)
python3 tests/run_all_tests.py
```

The test suite covers each detection layer plus a false-positive check that
confirms normal, varied traffic is never blocked.

## scaling

One instance tracks hundreds of agents at once. All state lives in memory —
no Redis, no database, no external dependencies. For most on-prem setups
that's the right trade: nothing to operate, sub-millisecond overhead.

To run several instances behind a load balancer, route by `X-Agent-ID` so each
agent consistently hits the same instance. Shared-state clustering is on the
roadmap — get in touch if you need it.

## license

NakshGuard v1 is open source under AGPL-3.0 — free to use, including internally,
with no obligation to release your own code. Commercial licensing (for
embedding in proprietary products, or for the Pro/Enterprise detection layers)
is available — see [COMMERCIAL.md](COMMERCIAL.md).

Built by a developer who got tired of agents quietly spending money.
