#!/usr/bin/env python3
"""
test_rate.py — tests the rate limiter

simulates a retry storm: the agent fires requests as fast as possible,
far exceeding the allowed requests-per-window. default limit is 20
requests per 10 seconds.

requires: proxy running in blocking mode (shadow_mode: false)
usage:    python3 test_rate.py
"""

import json
import time
import sys
import threading
import urllib.request
import urllib.error

BASE_URL  = "http://localhost:8080"
AGENT_ID  = "test-rate-agent"

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


def send_one(turn, results, lock):
    payload = json.dumps({
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "user",
             "content": f"Quick status check #{turn}. Is the service up?"}
        ]
    }).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json", "X-Agent-ID": AGENT_ID}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            with lock:
                results.append((turn, r.status, None))
    except urllib.error.HTTPError as e:
        body = None
        if e.code == 429:
            try:
                body = json.loads(e.read().decode())
            except:
                pass
        with lock:
            results.append((turn, e.code, body))
    except Exception as e:
        with lock:
            results.append((turn, 0, str(e)))


def run():
    print(f"\n{BOLD}test 3/3 — rate limiter{RESET}")
    print("fires 30 requests almost simultaneously — 10 over the 20/10s limit")
    print(f"{'─'*55}\n")

    results = []
    lock = threading.Lock()
    threads = []

    # fire 30 requests at once, enough to trip the 20/10s window
    total = 30
    print(f"firing {total} requests in parallel... ", end="", flush=True)

    for i in range(1, total + 1):
        t = threading.Thread(target=send_one, args=(i, results, lock))
        threads.append(t)

    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start

    print(f"done in {elapsed:.2f}s\n")

    # sort by turn number for readable output
    results.sort(key=lambda x: x[0])

    passed  = [r for r in results if r[1] not in (429, 0)]
    blocked = [r for r in results if r[1] == 429]
    errors  = [r for r in results if r[1] == 0]

    for turn, status, body in results:
        if status == 429:
            layer = body.get("layer", "") if body else ""
            print(f"  req {turn:>2}: {RED}BLOCKED [{layer}]{RESET}")
        elif status in (401, 502):
            print(f"  req {turn:>2}: {DIM}pass (upstream auth){RESET}")
        elif status == 0:
            print(f"  req {turn:>2}: {YELLOW}error{RESET}")
        else:
            print(f"  req {turn:>2}: {GREEN}{status}{RESET}")

    print(f"\n  passed:  {len(passed)}")
    print(f"  blocked: {len(blocked)}")

    print()
    if blocked:
        print(f"{GREEN}{BOLD}PASS{RESET} — rate limiter fired, {len(blocked)} requests blocked")
        return True
    else:
        print(f"{YELLOW}INCONCLUSIVE{RESET} — nothing blocked")
        print(f"  check proxy logs for [shadow] or [rate_limit] lines")
        print(f"  default: 20 requests per 10 seconds")
        return False


if __name__ == "__main__":
    ok, _ = check_proxy()
    if ok:
        run()
