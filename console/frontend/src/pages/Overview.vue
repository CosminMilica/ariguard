<script setup lang="ts">
import { computed } from 'vue'
import StatTiles from '../components/StatTiles.vue'
import Chart from '../components/Chart.vue'
import Chain from '../components/Chain.vue'
import { store, toMs, pad, nodeOk, setWindow } from '../api'

const evSeries = computed(() => store.overview?.events_series ?? [])
const labels = computed(() => evSeries.value.map(p => { const d = new Date(toMs(p.t)); return `${pad(d.getHours())}:${pad(d.getMinutes())}` }))
const series = computed(() => [{ label: 'events/s', data: evSeries.value.map(p => p.v), color: '#22c1c4' }])

const times = computed(() => evSeries.value.map(p => toMs(p.t)))

const states = [
  ['normal', '#3fb97f'], ['suspicious', '#e0a53a'], ['escalating', '#ef7d29'],
  ['breakout_imminent', '#f2623f'], ['compromised', '#f05568'],
] as const
const brk = computed(() => {
  const b = store.overview?.state_breakdown ?? {}
  const total = states.reduce((a, [k]) => a + (b[k] || 0), 0)
  return { total, rows: states.map(([k, c]) => ({ k, c, n: b[k] || 0, pct: total ? (((b[k] || 0) / total) * 100).toFixed(0) : '0' })) }
})
</script>

<template>
  <StatTiles />
  <section class="cols" style="margin-bottom:16px">
    <div class="card">
      <div class="hd"><h2>Syscall events</h2><span class="c">per second · {{ store.customFrom ? 'custom window' : store.range }}</span></div>
      <div class="bd">
        <div v-if="!evSeries.length" class="empty">No event data yet.</div>
        <div v-else class="chart-wrap"><Chart kind="line" :labels="labels" :series="series" :times="times" @brush="setWindow" /></div>
      </div>
    </div>
    <div class="card">
      <div class="hd"><h2>FSM state</h2><span class="c">{{ brk.total }} workloads</span></div>
      <div class="bd">
        <div v-if="!brk.total" class="empty">No workloads reported yet.</div>
        <div v-else class="brk">
          <div v-for="r in brk.rows" :key="r.k" class="row">
            <span>{{ r.k.replace('_', ' ') }}</span>
            <span class="track"><i :style="{ width: r.pct + '%', background: r.c }"></i></span>
            <span class="n">{{ r.n }}</span>
          </div>
        </div>
      </div>
    </div>
  </section>
  <section class="cols3">
    <Chain />
    <div class="card">
      <div class="hd"><h2>Rules</h2><span class="c">{{ store.rules.length }} loaded</span></div>
      <div class="bd">
        <div v-if="!store.rules.length" class="empty">No rules registered.</div>
        <div v-for="r in store.rules" :key="r.name" class="rule">
          <div><div class="nm">{{ r.name }}</div><div class="m">{{ r.num_states }} states · {{ r.scope }} · {{ r.terminal_action }}</div></div>
          <div class="h">{{ r.hits }}</div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="hd"><h2>Nodes</h2><span class="c">DaemonSet</span></div>
      <div class="scroll">
        <table>
          <thead><tr><th>Node</th><th>Kernel</th><th>Hooks</th><th>Status</th></tr></thead>
          <tbody>
            <tr v-if="!store.nodes.length"><td colspan="4" class="empty">No agents have registered.</td></tr>
            <tr v-for="n in store.nodes" :key="n.node">
              <td class="mono">{{ n.node }}</td><td class="mono dim">{{ n.kernel }}</td>
              <td class="mono">{{ n.hooks_attached }}/{{ n.hooks_total }}</td>
              <td><span class="st" :class="nodeOk(n.status) ? 'normal' : 'suspicious'">{{ n.status }}</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>
</template>
