// Package loader loads the Rust-built eBPF object and manages its maps.
package loader

// Map names from the kernel object contract (docs/architecture.md).
const (
	MapState       = "SW_STATE"
	MapTransitions = "SW_TRANSITIONS"
	MapBindings    = "SW_BINDINGS"
	MapRules       = "SW_RULES"
	MapPolicy      = "SW_POLICY"
	MapAudit       = "SW_AUDIT"
	MapScratch     = "SW_SCRATCH"
	MapPods        = "SW_PODS"
	MapMetrics     = "SW_METRICS"
)

// MapNames lists every contract map.
var MapNames = []string{MapState, MapTransitions, MapBindings, MapRules, MapPolicy, MapAudit, MapScratch, MapPods, MapMetrics}

// ProgramPrefix marks the statewall tracepoint programs.
const ProgramPrefix = "sw_"
