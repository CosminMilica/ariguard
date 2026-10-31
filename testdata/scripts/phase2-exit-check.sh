#!/usr/bin/env bash
# Phase 2 exit check (EVAL-2.3): the Phase 1 exit check with enforcement on.
set -euo pipefail
STATEWALL_ENFORCE=1 exec "$(dirname "${BASH_SOURCE[0]}")/phase1-exit-check.sh" "$@"
