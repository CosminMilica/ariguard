// Package loader loads the Rust-built eBPF object and manages its maps.
package loader

// Map names from the kernel object contract (docs/architecture.md).
const (
	MapState       = "SW_STATE"
	MapTransitions = "SW_TRANSITIONS"
	MapBindings    = "SW_BINDINGS"
	MapDims        = "SW_DIMS"
	MapAudit       = "SW_AUDIT"
	MapScratch     = "SW_SCRATCH"
)

// ProgramPrefix marks the statewall tracepoint programs.
const ProgramPrefix = "sw_"
