<script setup lang="ts">
import { computed } from 'vue'
import ContainmentBar from '../components/ContainmentBar.vue'
import QuarantineBadge from '../components/QuarantineBadge.vue'
import { store, clockNs, toMs, openChainModal, exportIncident, type TriageRow } from '../api'

const stateLabel = (s: string) => (s || '').replace(/_/g, ' ')
const key = (t: TriageRow) => t.pod + t.started_ts_ns

const outcome = (o: string) => {
  const k = (o || '').toLowerCase()
  if (k === 'killed') return { text: 'killed', cls: 'act kill' }
  if (k === 'blocked') return { text: 'blocked', cls: 'act deny' }
  return { text: 'detected', cls: 'act' }
}

function age(ns: number) {
  const s = Math.max(0, (Date.now() - toMs(ns)) / 1000)
  if (s >= 3600) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
  if (s >= 60) return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`
  return `${Math.floor(s)}s`
}

const activeCount = computed(() => store.triage.filter(t => t.active).length)
const containedCount = computed(() => store.triage.filter(t => ['killed', 'blocked'].includes((t.outcome || '').toLowerCase())).length)

function onExport(e: Event, pod: string) {
  e.stopPropagation()
  exportIncident(pod)
}
</script>

<template>
  <ContainmentBar />
  <section class="card">
    <div class="hd">
      <h2>Live threats</h2>
      <span class="c">{{ activeCount }} active · {{ containedCount }} contained</span>
    </div>
    <div class="bd" v-if="!store.triage.length">
      <div class="empty">No live threats in this range.</div>
    </div>
    <div class="scroll" v-else>
      <table>
        <thead>
          <tr>
            <th></th><th>State</th><th>Rule</th><th>Pod</th><th>Namespace</th><th>Node</th>
            <th>Steps</th><th>Age</th><th>Last seen</th><th>Outcome</th><th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="t in store.triage" :key="key(t)" class="clickrow" @click="openChainModal(t.pod)">
            <td><span class="live" :class="{ on: t.active }" :title="t.active ? 'active' : 'resolved'"></span></td>
            <td><span class="st" :class="t.max_state">{{ stateLabel(t.max_state) }}</span></td>
            <td>{{ t.rule }}</td>
            <td class="mono">{{ t.pod }}</td>
            <td class="mono dim">{{ t.namespace }}</td>
            <td class="mono dim">{{ t.node }}</td>
            <td class="mono">{{ t.steps }}</td>
            <td class="mono">{{ age(t.started_ts_ns) }}</td>
            <td class="mono dim">{{ clockNs(t.last_ts_ns) }}</td>
            <td><span :class="outcome(t.outcome).cls">{{ outcome(t.outcome).text }}</span><QuarantineBadge v-if="t.quarantined" class="qb" /></td>
            <td class="right"><button class="btn" @click="onExport($event, t.pod)">Export</button></td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.clickrow { cursor:pointer; }
.qb { margin-left:8px; vertical-align:middle; }
.live { display:inline-block; width:9px; height:9px; border-radius:50%; background:var(--faint); }
.live.on { background:var(--crit); box-shadow:0 0 0 0 color-mix(in srgb, var(--crit) 70%, transparent); animation:pulse 1.6s infinite; }
@keyframes pulse {
  0% { box-shadow:0 0 0 0 color-mix(in srgb, var(--crit) 70%, transparent); }
  70% { box-shadow:0 0 0 6px transparent; }
  100% { box-shadow:0 0 0 0 transparent; }
}
</style>
