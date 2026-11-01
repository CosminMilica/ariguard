<script setup lang="ts">
import { computed } from 'vue'
import { store, fmtNum, fmtBytes } from '../api'

const p = computed(() => store.perf)

const programs = computed(() => {
  const list = store.perf?.programs ?? []
  return [...list].sort(
    (a, b) => (a.runs === 0 ? 1 : 0) - (b.runs === 0 ? 1 : 0) || b.ns_per_run - a.ns_per_run,
  )
})

const maxNs = computed(() =>
  Math.max(1, ...programs.value.filter(x => x.runs > 0).map(x => x.ns_per_run)),
)

function fmtNs(ns: number): string {
  if (ns == null || isNaN(ns)) return '—'
  if (ns >= 1000) return `${fmtNum(ns / 1000)} µs`
  return `${fmtNum(ns)} ns`
}

const tiles = computed(() => {
  const d = store.perf
  return [
    { k: 'Events / sec', v: d ? fmtNum(d.events_per_sec) : '—', d: 'live', c: 'teal' },
    { k: 'Memory (BPF maps)', v: d ? fmtBytes(d.bpf_map_bytes) : '—', d: 'pre-allocated · flat', c: '' },
    { k: 'Audit dropped', v: d ? String(d.audit_dropped) : '—', d: d && d.audit_dropped ? 'events lost' : 'ringbuf ok', c: d && d.audit_dropped ? 'crit' : '' },
  ]
})
</script>

<template>
  <section v-if="!p" class="card">
    <div class="hd"><h2>Performance</h2><span class="c">live</span></div>
    <div class="empty">Waiting for agent performance metrics…</div>
  </section>

  <template v-else>
    <section class="stats perf">
      <div v-for="t in tiles" :key="t.k" class="stat">
        <div class="k">{{ t.k }}</div>
        <div class="v" :class="t.c">{{ t.v }}</div>
        <div class="d">{{ t.d }}</div>
      </div>
    </section>

    <section class="card">
      <div class="hd"><h2>Overhead per hook</h2><span class="c">ns / event (BPF run-time)</span></div>
      <div class="scroll">
        <table v-if="programs.length">
          <thead><tr><th>Program</th><th>ns / event (BPF run-time)</th><th>Runs</th></tr></thead>
          <tbody>
            <tr v-for="pr in programs" :key="pr.program" :class="{ idle: pr.runs === 0 }">
              <td class="mono">{{ pr.program }}</td>
              <td>
                <span class="bar"><i :style="{ width: (pr.runs > 0 ? (pr.ns_per_run / maxNs) * 100 : 0) + '%' }"></i></span>
                <span class="mono val">{{ pr.runs > 0 ? fmtNs(pr.ns_per_run) : '—' }}</span>
              </td>
              <td class="mono">{{ fmtNum(pr.runs) }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">enable --bpf-stats on the agent for per-hook overhead</div>
      </div>
    </section>

    <p class="perf-note">
      Figures are in-kernel BPF run-time per event — the overhead each hook adds inline to the
      syscall — on top of a flat, pre-allocated BPF-map memory budget that never grows (zero-allocation design).
    </p>
  </template>
</template>

<style scoped>
.stats.perf { grid-template-columns: repeat(3, 1fr); }
@media (max-width: 640px) { .stats.perf { grid-template-columns: 1fr; } }
.bar { margin-right: 10px; }
td .val { color: var(--fg-2); }
tbody tr.idle td { color: var(--faint); }
.perf-note { color: var(--faint); font-size: 12px; line-height: 1.5; margin: 14px 2px 0; max-width: 760px; }
</style>
