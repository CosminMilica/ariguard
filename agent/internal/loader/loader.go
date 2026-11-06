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
	MapConnDst     = "AG_CONNDST"
	MapPath        = "AG_PATH"
	MapArgv        = "AG_ARGV"
	MapLearn       = "AG_LEARN"      // ring of raw learn-mode syscall records (F11)
	MapLearnPods   = "AG_LEARN_PODS" // opt-in cgroup set for learn-mode (F11)
)

// MapNames lists every contract map.
var MapNames = []string{MapState, MapTransitions, MapBindings, MapRules, MapPolicy, MapAudit, MapScratch, MapPods, MapMetrics, MapPpid, MapConnDst, MapPath, MapArgv, MapLearn, MapLearnPods}

// LearnPrograms are the dedicated learn-mode emitters — a second program on each sys_enter_<hook>
// tracepoint (F11). Attached only while learn-mode is on, to avoid hot-path overhead when off.
var LearnPrograms = map[string]string{
	"sw_openat_learn":       "sys_enter_openat",
	"sw_setns_learn":        "sys_enter_setns",
	"sw_unshare_learn":      "sys_enter_unshare",
	"sw_mount_learn":        "sys_enter_mount",
	"sw_execve_learn":       "sys_enter_execve",
	"sw_ptrace_learn":       "sys_enter_ptrace",
	"sw_connect_learn":      "sys_enter_connect",
	"sw_dup2_learn":         "sys_enter_dup2",
	"sw_dup3_learn":         "sys_enter_dup3",
	"sw_memfd_create_learn": "sys_enter_memfd_create",
	"sw_execveat_learn":     "sys_enter_execveat",
	"sw_fsmount_learn":      "sys_enter_fsmount",
	"sw_move_mount_learn":   "sys_enter_move_mount",
	"sw_init_module_learn":  "sys_enter_init_module",
	"sw_finit_module_learn": "sys_enter_finit_module",
	"sw_bpf_learn":          "sys_enter_bpf",
}

// ProgramPrefix marks the ariguard tracepoint programs.
const ProgramPrefix = "sw_"

// ForkProgram records parent->child on sched_process_fork to populate AG_PPID (process ancestry).
const ForkProgram = "trace_fork"

// ArgvPrograms capture exec argv (B3) as a second program on the execve/execveat tracepoints — kept
// separate from sw_execve/sw_execveat so the bounded read loop has its own verifier budget.
var ArgvPrograms = map[string]string{
	"sw_execve_argv":   "sys_enter_execve",
	"sw_execveat_argv": "sys_enter_execveat",
}

// LSMProgramPrefix marks the ariguard BPF LSM deny programs.
const LSMProgramPrefix = "lsm_"
