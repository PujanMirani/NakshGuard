# integration tests

These hit a running proxy over HTTP and check that each detection layer
actually fires. They're separate from the Go unit tests (`session_test.go` in
the root), which test the detection logic directly without a server.

## running them

Start the proxy in blocking mode first — set `shadow_mode: false` in
`proxy.yaml`, then:

```bash
go run .                      # in the project root, one terminal
python3 tests/run_all_tests.py  # in another terminal
```

## what each one does

| file                     | layer tested | how |
|--------------------------|--------------|-----|
| test_growth.py           | cve          | grows the conversation each turn, like an error-append loop |
| test_repeat.py           | repetition   | sends the identical request over and over |
| test_rate.py             | rate limit   | fires a burst of parallel requests |
| test_false_positive.py   | none (!)     | sends normal varied traffic — must never block |

`test_false_positive.py` is the important one. A loop detector that blocks
legitimate work is worse than no detector. If it ever fails, the thresholds
are too tight.

`run_all_tests.py` runs all four and prints a pass/fail summary.

No API key needed — detection runs before anything is forwarded, so requests
get blocked (or pass through to a harmless upstream 401) at the proxy itself.
