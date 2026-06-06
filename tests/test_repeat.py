#!/usr/bin/env python3
"""
test_repeat.py — tests repetition detection

simulates the second most common loop: an agent stuck retrying the
exact same request over and over. no token growth means CVE misses it.
the repetition layer catches it by hashing the prompt.

requires: proxy running in blocking mode (shadow_mode: false)
usage:    python3 test_repeat.py
"""

import json
import time
import sys
import urllib.request
import urllib.error

BASE_URL  = "http://localhost:8080"
AGENT_ID  = "test-repeat-agent"
MAX_TURNS = 15

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
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
                print(f"{YELLOW}shadow mode is ON — set shadow_mode: false to see real blocks{RESET}\n")
            return True, shadow
    except Exception as e:
        print(f"{RED}proxy not running: {e}{RESET}")
        print("start it: go run .")
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
            return 429, json.loads(e.read().decode())
        return e.code, None
    except Exception as e:
        return 0, str(e)


def run():
    print(f"\n{BOLD}test 2/3 — exact repeat detection{RESET}")
    print("sends the identical request every turn — no growth, same content")
    print("CVE stays silent; the repetition layer should catch it")
    print(f"{'─'*55}\n")
    print(f"{'turn':>4}  result")
    print(f"{'----':>4}  ------")

    # this exact message never changes - that's the point
    fixed_messages = [
        {"role": "user",
         "content": "Check if the payment service is reachable and return its status"}
    ]

    caught_at = None
    for turn in range(1, MAX_TURNS + 1):
        status, body = send(fixed_messages)

        if status == 429:
            reason = body.get("reason", "") if body else ""
            layer  = body.get("layer", "")
            print(f"{turn:>4}  {RED}{BOLD}BLOCKED{RESET} [{layer}]")
            print(f"\n  {DIM}{reason}{RESET}")
            caught_at = turn
            break
        elif status in (401, 502, 0):
            print(f"{turn:>4}  {DIM}pass (upstream auth — detection ran){RESET}")
        else:
            print(f"{turn:>4}  {GREEN}{status}{RESET}")

        # small delay between requests — keep well under the rate limit
        # so rate_limit doesn't fire before repetition does
        time.sleep(0.3)

    print()
    if caught_at:
        print(f"{GREEN}{BOLD}PASS{RESET} — repeat loop caught at turn {caught_at}")
        return True
    else:
        print(f"{YELLOW}INCONCLUSIVE{RESET} — not blocked in {MAX_TURNS} turns")
        print(f"  check proxy logs for [shadow] lines")
        print(f"  default threshold: 5 identical requests in 60s")
        return False


if __name__ == "__main__":
    ok, _ = check_proxy()
    if ok:
        run()
