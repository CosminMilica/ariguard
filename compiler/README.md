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
statewall-compile --input rules/container-escape.yml --out policies/container-escape.bin
```
