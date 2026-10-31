#!/usr/bin/env bash
# Phase 2b exit check (EVAL-2.3): the Phase 1 exit check with enforcement and deny-mode on.
set -euo pipefail
ARIGUARD_ENFORCE=1 ARIGUARD_DENY=1 exec "$(dirname "${BASH_SOURCE[0]}")/phase1-exit-check.sh" "$@"
