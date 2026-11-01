// Package loader loads the Rust-built eBPF object and manages its maps.
package loader

// Map names from the kernel object contract (docs/architecture.md).
const (
	MapState       = "AG_STATE"
	MapTransitions = "AG_TRANSITIONS"
	MapBindings    = "AG_BINDINGS"
	MapRules       = "AG_RULES"
	MapPolicy      = "AG_POLICY"
	MapAudit       = "AG_AUDIT"
	MapScratch     = "AG_SCRATCH"
	MapPods        = "AG_PODS"
	MapMetrics     = "AG_METRICS"
	MapPpid        = "AG_PPID"
)

// MapNames lists every contract map.
var MapNames = []string{MapState, MapTransitions, MapBindings, MapRules, MapPolicy, MapAudit, MapScratch, MapPods, MapMetrics, MapPpid}

// ProgramPrefix marks the ariguard tracepoint programs.
const ProgramPrefix = "sw_"

// ForkProgram records parent->child on sched_process_fork to populate AG_PPID (process ancestry).
const ForkProgram = "trace_fork"

// LSMProgramPrefix marks the ariguard BPF LSM deny programs.
const LSMProgramPrefix = "lsm_"
