#!/usr/bin/env python3
"""
test_false_positive.py — the most important test of all

sends normal, varied, non-looping traffic and verifies the proxy
never blocks any of it. a loop detector that blocks legitimate work
is worse than no detector at all.

requires: proxy running (shadow mode on or off — both should pass)
usage:    python3 test_false_positive.py
"""

import json
import time
import sys
import urllib.request
import urllib.error

BASE_URL = "http://localhost:8080"
AGENT_ID = "test-innocent-agent"

RED   = "\033[91m"
GREEN = "\033[92m"
DIM   = "\033[2m"
BOLD  = "\033[1m"
RESET = "\033[0m"


def check_proxy():
    try:
        with urllib.request.urlopen(f"{BASE_URL}/health", timeout=3) as r:
            h = json.loads(r.read())
            print(f"proxy {h.get('version')} · "
                  f"shadow={'on' if h.get('shadow') else 'off'}")
            return True
    except Exception as e:
        print(f"{RED}proxy not running: {e}{RESET}")
        print("start it: go run .")
        return False


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
            return 429, json.loads(e.read().decode())
        return e.code, None
    except Exception as e:
        return 0, str(e)


# 12 genuinely different requests — varied sizes, topics, phrasing.
# nothing here should trigger any detection layer.
NORMAL_REQUESTS = [
    [{"role": "user", "content": "What is the capital of France?"}],
    [{"role": "user", "content": "Write a Python function that reverses a string"}],
    [{"role": "user", "content": "Explain the difference between TCP and UDP in one paragraph"}],
    [{"role": "user", "content": "What is 2 to the power of 10?"}],
    [{"role": "user", "content": "Summarise what a REST API is in two sentences"}],
    [{"role": "user", "content": "Give me three names for a new coffee brand"}],
    [{"role": "user", "content": "What does idempotent mean in software engineering?"}],
    [{"role": "user", "content": "Convert 100 USD to approximate INR"}],
    [{"role": "user", "content": "What is the time complexity of binary search?"}],
    [{"role": "user", "content": "Write a haiku about debugging code at 2am"}],
    [{"role": "user", "content": "Name five open source databases"}],
    [{"role": "user", "content": "What are the SOLID principles in object-oriented design?"}],
]


def run():
    print(f"\n{BOLD}test 4/3 — false positive check{RESET}")
    print("normal varied traffic — proxy must NOT block any of these")
    print(f"{'─'*55}\n")
    print(f"{'req':>3}  {'result':>8}  prompt")
    print(f"{'---':>3}  {'------':>8}  ------")

    false_positives = []

    for i, messages in enumerate(NORMAL_REQUESTS, 1):
        prompt_preview = messages[-1]["content"][:45]
        status, body = send(messages)

        if status == 429:
            reason = body.get("reason", "") if body else ""
            print(f"{i:>3}  {RED}{'BLOCKED':>8}{RESET}  {prompt_preview}")
            print(f"       {DIM}^ {reason}{RESET}")
            false_positives.append((i, reason))
        elif status in (401, 502):
            print(f"{i:>3}  {DIM}{'ok':>8}{RESET}  {prompt_preview}")
        elif status == 0:
            print(f"{i:>3}  {'error':>8}  {prompt_preview}")
        else:
            print(f"{i:>3}  {GREEN}{status:>8}{RESET}  {prompt_preview}")

        # deliberate spacing — real users don't fire 12 requests in 0.1s
        time.sleep(0.5)

    print()
    if not false_positives:
        print(f"{GREEN}{BOLD}PASS{RESET} — zero false positives across "
              f"{len(NORMAL_REQUESTS)} varied requests")
        return True
    else:
        print(f"{RED}{BOLD}FAIL{RESET} — {len(false_positives)} false positive(s):")
        for i, reason in false_positives:
            print(f"  request {i}: {reason}")
        print()
        print("this means the proxy is blocking legitimate traffic.")
        print("check your proxy.yaml thresholds — they may be too tight.")
        return False


if __name__ == "__main__":
    if check_proxy():
        run()
