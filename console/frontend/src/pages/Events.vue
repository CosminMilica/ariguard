<script setup lang="ts">
import { computed } from 'vue'
import Chart from '../components/Chart.vue'
import Feed from '../components/Feed.vue'
import { store, sevKey, pad, hasWindow, setWindow } from '../api'

const chips = [['all', 'All'], ['crit', 'Critical'], ['mid', 'Escalating'], ['warn', 'Suspicious']]

const buckets = computed(() => {
  const spec = { '15m': [15, 60e3], '1h': [12, 300e3], '24h': [24, 3600e3] }[store.range]
  const custom = hasWindow()
  const n = custom ? 24 : spec[0]
  const size = custom ? (store.customTo - store.customFrom) / n : spec[1]
  const start = custom ? store.customFrom : Math.ceil(Date.now() / size) * size - n * size
  const out = { crit: Array(n).fill(0), mid: Array(n).fill(0), warn: Array(n).fill(0) } as Record<string, number[]>
  for (const e of store.allEvents) {
    const ms = e.ts_ns / 1e6
    const i = Math.floor((ms - start) / size)
    const k = sevKey(e.severity)
    if (i >= 0 && i < n && out[k]) out[k][i]++
  }
  const labels = Array.from({ length: n }, (_, i) => { const d = new Date(start + i * size); return !custom && store.range === '24h' ? `${pad(d.getHours())}:00` : `${pad(d.getHours())}:${pad(d.getMinutes())}` })
  const times = Array.from({ length: n }, (_, i) => start + i * size)
  return { labels, out, times, size }
})
const series = computed(() => [
  { label: 'suspicious', data: buckets.value.out.warn, color: '#e0a53a' },
  { label: 'escalating', data: buckets.value.out.mid, color: '#ef7d29' },
  { label: 'killed', data: buckets.value.out.crit, color: '#f05568' },
])
</script>

<template>
  <section class="card" style="margin-bottom:16px">
    <div class="hd"><h2>Severity timeline</h2><span class="c">{{ store.range }}</span></div>
    <div class="bd">
      <div v-if="!store.allEvents.length" class="empty">No events in this range.</div>
      <div v-else class="chart-wrap sm"><Chart kind="bar" :labels="buckets.labels" :series="series" :times="buckets.times" :step="buckets.size" legend @brush="setWindow" /></div>
    </div>
  </section>
  <section class="card">
    <div class="hd"><h2>Events</h2><span class="c">{{ store.events.length }} events</span></div>
    <div class="toolbar">
      <button v-for="c in chips" :key="c[0]" class="chip-f" :class="{ on: store.evSev === c[0] }" @click="store.evSev = c[0]">{{ c[1] }}</button>
      <span class="sep"></span>
      <button class="chip-f" :class="{ on: !store.evAll }" @click="store.evAll = false">Signal</button>
      <button class="chip-f" :class="{ on: store.evAll }" @click="store.evAll = true">All (incl. observe)</button>
      <div class="search">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3-3"/></svg>
        <input v-model="store.evQ" placeholder="Search pod, rule, node…">
      </div>
    </div>
    <div class="bd"><Feed :events="store.events" /></div>
  </section>
</template>
