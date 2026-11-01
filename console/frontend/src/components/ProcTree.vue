<script setup lang="ts">
import { computed } from 'vue'
import { actLabel, procLabel, isKill, isDeny, type ChainStep } from '../api'

// This component is recursive: the top-level call passes `steps` and renders the
// derived roots; recursive calls pass a single `node`.
const props = defineProps<{ steps?: ChainStep[]; node?: Pnode; depth?: number }>()

interface Pnode {
  pid: number
  comm: string
  ppid: number
  hooks: string[]
  worst: { text: string; cls: string }
  crit: boolean
  children: Pnode[]
}

function sevRank(action: string, enforced: boolean): number {
  if (isKill(action)) return enforced ? 4 : 2
  if (isDeny(action)) return enforced ? 3 : 1
  return 0
}

// Collapse the chain into distinct processes (by pid) and link each to its
// parent via ppid. Roots are processes whose ppid is not itself in the chain —
// the attack's entry point / outside ancestor.
const roots = computed<Pnode[]>(() => {
  const steps = props.steps || []
  const pids = new Set(steps.map(s => s.pid ?? 0))
  const nodes = new Map<number, Pnode>()
  const rank = new Map<number, number>()

  for (const s of steps) {
    const pid = s.pid ?? 0
    let n = nodes.get(pid)
    if (!n) {
      n = { pid, comm: s.comm || '', ppid: s.ppid ?? 0, hooks: [], worst: actLabel('observe', false), crit: false, children: [] }
      nodes.set(pid, n)
      rank.set(pid, -1)
    }
    const hk = s.hook || s.event
    if (hk && !n.hooks.includes(hk)) n.hooks.push(hk)
    const r = sevRank(s.action, s.enforced)
    if (r > (rank.get(pid) ?? -1)) {
      rank.set(pid, r)
      n.worst = actLabel(s.action, s.enforced)
    }
    if (s.enforced && (isKill(s.action) || isDeny(s.action))) n.crit = true
  }

  const out: Pnode[] = []
  for (const n of nodes.values()) {
    const parent = nodes.get(n.ppid)
    if (parent && parent.pid !== n.pid) parent.children.push(n)
    else out.push(n)
  }
  return out
})

const hasAncestry = computed(() => (props.steps || []).some(s => (s.ppid ?? 0) > 0))
const label = (n: Pnode) => procLabel(n.comm, n.pid) || `[${n.pid}]`
const d = computed(() => props.depth ?? 0)
</script>

<template>
  <!-- root entry point: the public `steps` prop -->
  <div v-if="props.steps" class="ptree">
    <div v-if="!hasAncestry" class="pt-note">No ancestry captured — showing flat timeline below.</div>
    <ul v-else class="pt-list pt-root">
      <ProcTree v-for="r in roots" :key="r.pid" :node="r" :depth="0" />
    </ul>
  </div>

  <!-- recursive node -->
  <li v-else-if="props.node" class="pt-node">
    <div class="pt-row" :class="{ crit: props.node.crit }">
      <span class="pt-proc mono">{{ label(props.node) }}</span>
      <span class="pt-chips">
        <span v-for="h in props.node.hooks" :key="h" class="pt-hook mono">{{ h }}</span>
      </span>
      <span class="pt-act" :class="props.node.worst.cls">{{ props.node.worst.text }}</span>
    </div>
    <ul v-if="props.node.children.length" class="pt-list">
      <ProcTree v-for="c in props.node.children" :key="c.pid" :node="c" :depth="d + 1" />
    </ul>
  </li>
</template>

<style scoped>
.ptree { padding: 2px 2px 14px; margin-bottom: 12px; border-bottom: 1px solid var(--border); }
.pt-note { font-size: 12px; color: var(--faint); font-style: italic; }
.pt-list { list-style: none; margin: 0; padding: 0; }
.pt-root { margin-top: 2px; }
.pt-node .pt-list { margin-left: 10px; padding-left: 12px; border-left: 1px solid var(--border); }
.pt-row { display: flex; align-items: center; gap: 10px; padding: 4px 2px; flex-wrap: wrap; }
.pt-proc { font-size: 12.5px; font-weight: 600; color: var(--fg); }
.pt-row.crit .pt-proc { color: var(--crit); }
.pt-chips { display: flex; gap: 5px; flex-wrap: wrap; }
.pt-hook { font-size: 10.5px; color: var(--teal); background: color-mix(in srgb, var(--teal) 12%, transparent); border: 1px solid var(--border); border-radius: 999px; padding: 1px 7px; }
.pt-act { margin-left: auto; font-size: 11.5px; }
</style>
