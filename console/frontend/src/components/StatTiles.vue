<script setup lang="ts">
import { computed } from 'vue'
import { store, fmtNum } from '../api'

const tiles = computed(() => {
  const k = store.overview?.kpis
  const hooks = store.nodes.reduce((a, n) => a + n.hooks_total, 0)
  const healthy = store.nodes.filter(n => ['ready', 'healthy', 'up', 'ok', 'online'].includes(n.status?.toLowerCase())).length
  return [
    { k: 'Workloads', v: k ? String(k.workloads) : '—', d: `${store.nodes.length} nodes`, c: '' },
    { k: 'Events / sec', v: k ? fmtNum(k.events_per_sec) : '—', d: `last ${store.range}`, c: 'teal' },
    { k: 'Mitigations', v: k ? String(k.kills) : '—', d: k ? `${fmtNum(k.kills_total ?? 0)} total` : '', c: 'crit' },
    { k: 'Audit dropped', v: k ? String(k.audit_dropped) : '—', d: k && k.audit_dropped ? 'events lost' : 'ringbuf ok', c: '' },
    { k: 'Rules', v: k ? String(k.rules) : '—', d: `${hooks} hooks`, c: '' },
    { k: 'Agents', v: k ? `${healthy}/${k.agents}` : '—', d: 'healthy', c: 'teal' },
  ]
})
</script>

<template>
  <section class="stats">
    <div v-for="t in tiles" :key="t.k" class="stat">
      <div class="k">{{ t.k }}</div>
      <div class="v" :class="t.c">{{ t.v }}</div>
      <div class="d">{{ t.d }}</div>
    </div>
  </section>
</template>
