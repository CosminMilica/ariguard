# compiler — threat intelligence → FSM tables (Python)

Turns high-level threat intelligence into the compact transition tables loaded into the
kernel. Runs **offline, at compile time** — never on the data path.

- **sigma** — translate ATT&CK techniques / Sigma rules (incl. an optional LLM path for
  natural-language → FSM).
- **mine** — mine malicious subsequences from labeled syscall traces (ML path).
- **emit** — serialize the resulting FSM into the on-wire transition-table format the
  control plane distributes to agents.

## Usage (planned)

```sh
pip install -e .
ariguard-compile --rules-dir rules --out policies/policy.bin   # or repeat --input FILE
```

## Bundles

Two bundles are produced from the same compiler:

- **Deploy bundle** — `make bundle` → `testdata/golden/policy-full.bin`, the full
  rule library (7 rules); this is what the agent image ships.
- **Golden parity fixture** — `testdata/golden/policy.bin`, the 3 native rules,
  kept as the byte-for-byte parity fixture.

A guard test (`compiler/tests/test_bundle.py`) fails on drift between the bundle
and the rule library.
