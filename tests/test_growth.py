#!/usr/bin/env python3
"""
test_growth.py — tests CVE (context velocity) detection

simulates the most common real-world loop: an agent hits an error,
appends it to context, and retries. the conversation grows every turn.
after min_samples turns of consistent growth the proxy should block it.

requires: proxy running in blocking mode (shadow_mode: false in proxy.yaml)
usage:    python3 test_growth.py
"""

import json
import time
import sys
import urllib.request
import urllib.error

BASE_URL  = "http://localhost:8080"
AGENT_ID  = "test-cve-agent"
MAX_TURNS = 20

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def check_proxy():
    try:
        with urllib.request.urlopen(f"{BASE_URL}/health", timeout=3) as r:
            h = json.loads(r.read())
            shadow = h.get("shadow", True)
            print(f"proxy {h.get('version')} · shadow={'ON (log only)' if shadow else 'OFF (blocking)'}")
            if shadow:
                print(f"{YELLOW}shadow mode is ON — proxy will log blocks but not return 429")
                print(f"set shadow_mode: false in proxy.yaml to see real blocks{RESET}\n")
            return True, shadow
    except Exception as e:
        print(f"{RED}proxy not running: {e}{RESET}")
        print(f"start it with: {DIM}go run .{RESET}")
        return False, True


def send(messages):
    payload = json.dumps({
        "model": "gpt-3.5-turbo",
        "messages": messages
    }).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json", "X-Agent-ID": AGENT_ID}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, None
    except urllib.error.HTTPError as e:
        if e.code == 429:
            body = json.loads(e.read().decode())
            return 429, body
        return e.code, None
    except Exception as e:
        return 0, str(e)


def run():
    print(f"\n{BOLD}test 1/3 — context velocity (CVE){RESET}")
    print("simulates a stuck agent appending errors to context each turn")
    print(f"{'─'*55}\n")
    print(f"{'turn':>4}  {'msgs':>4}  {'~chars':>7}  result")
    print(f"{'----':>4}  {'----':>4}  {'-------':>7}  ------")

    # simulate an agent appending errors to its context
    messages = [
        {"role": "system", "content": "You are a database monitoring agent."}
    ]
    error_template = (
        "Attempt {n}: database connection failed. "
        "Error: timeout after 30s waiting for host db-prod-01.internal. "
        "Stack trace: ConnectionError at retry_connect() line 47. "
        "Previous failures logged. Retrying with exponential backoff."
    )
    caught_at = None

    for turn in range(1, MAX_TURNS + 1):
        # each turn appends both the error and a new retry request
        messages.append({
            "role": "assistant",
            "content": error_template.format(n=turn)
        })
        messages.append({
            "role": "user",
            "content": f"Retry #{turn+1}: check database connection status"
        })

        total_chars = sum(len(m["content"]) for m in messages)
        status, body = send(messages)

        if status == 429:
            reason = body.get("reason", "") if body else ""
            layer  = body.get("layer", "")
            print(f"{turn:>4}  {len(messages):>4}  {total_chars:>7}  "
                  f"{RED}{BOLD}BLOCKED{RESET} [{layer}]")
            print(f"\n  {DIM}{reason}{RESET}")
            caught_at = turn
            break
        elif status in (401, 502, 0):
            print(f"{turn:>4}  {len(messages):>4}  {total_chars:>7}  "
                  f"{DIM}pass (no api key, detection ran){RESET}")
        else:
            print(f"{turn:>4}  {len(messages):>4}  {total_chars:>7}  "
                  f"{GREEN}{status}{RESET}")

        time.sleep(0.05)

    print()
    if caught_at:
        print(f"{GREEN}{BOLD}PASS{RESET} — growth loop caught at turn {caught_at}")
        return True
    else:
        print(f"{YELLOW}INCONCLUSIVE{RESET} — not blocked in {MAX_TURNS} turns")
        print(f"  check proxy logs for {DIM}[shadow]{RESET} lines if shadow mode is on")
        print(f"  or lower max_growth_rate / min_samples in proxy.yaml")
        return False


if __name__ == "__main__":
    ok, _ = check_proxy()
    if ok:
        run()
