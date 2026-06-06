#!/usr/bin/env python3
"""
run_all_tests.py — runs all four V1 detection tests in sequence

each test targets a different detection layer:
  test 1 (growth)         → CVE, context velocity
  test 2 (repeat)         → repetition detection
  test 3 (rate)           → rate limiter
  test 4 (false positive) → no blocking on normal traffic

setup:
  1. open proxy.yaml and set shadow_mode: false
  2. start the proxy:  go run .
  3. run this:         python3 run_all_tests.py

the proxy must be in BLOCKING mode (shadow_mode: false) for tests 1-3 to
get proper PASS/FAIL results. in shadow mode the proxy logs detections but
lets everything through, so the tests show INCONCLUSIVE.
"""

import sys
import importlib.util
import os

RED   = "\033[91m"
GREEN = "\033[92m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RESET = "\033[0m"


def load_and_run(filename, fn_name="run"):
    path = os.path.join(os.path.dirname(__file__), filename)
    spec = importlib.util.spec_from_file_location("mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, fn_name)()


def main():
    print(f"\n{'='*55}")
    print(f"{BOLD}  nakshguard V1 — detection test suite{RESET}")
    print(f"{'='*55}\n")

    # check proxy once, shared by all tests
    import urllib.request, json
    try:
        with urllib.request.urlopen("http://localhost:8080/health", timeout=3) as r:
            h = json.loads(r.read())
            shadow = h.get("shadow", True)
            print(f"proxy v{h.get('version')} is running")
            if shadow:
                print(f"\n{RED}WARNING: shadow_mode is ON{RESET}")
                print("tests 1-3 will show INCONCLUSIVE instead of PASS")
                print("set shadow_mode: false in proxy.yaml and restart\n")
                ans = input("continue anyway? [y/N] ").strip().lower()
                if ans != "y":
                    sys.exit(0)
    except Exception as e:
        print(f"{RED}proxy not running: {e}{RESET}")
        print("start it:  go run .")
        sys.exit(1)

    tests = [
        ("test_growth.py",         "Growth loop (CVE)"),
        ("test_repeat.py",         "Repeat loop (repetition)"),
        ("test_rate.py",           "Rate storm (rate limiter)"),
        ("test_false_positive.py", "Normal traffic (no false positives)"),
    ]

    results = []
    for filename, label in tests:
        print(f"\n{'─'*55}")
        try:
            passed = load_and_run(filename)
            results.append((label, passed))
        except Exception as e:
            print(f"{RED}error running {filename}: {e}{RESET}")
            results.append((label, None))

    # summary
    print(f"\n{'='*55}")
    print(f"{BOLD}  results{RESET}")
    print(f"{'='*55}")
    all_pass = True
    for label, passed in results:
        if passed is True:
            icon = f"{GREEN}PASS{RESET}"
        elif passed is False:
            icon = f"{RED}FAIL{RESET}"
            all_pass = False
        else:
            icon = f"{DIM}ERROR{RESET}"
            all_pass = False
        print(f"  {icon}  {label}")

    print()
    if all_pass:
        print(f"{GREEN}{BOLD}all tests passed — proxy is working correctly{RESET}")
    else:
        print(f"{RED}some tests failed — check the output above{RESET}")
    print()


if __name__ == "__main__":
    main()
