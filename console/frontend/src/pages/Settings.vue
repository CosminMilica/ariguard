<script setup lang="ts">
import { computed } from 'vue'
import { store, fmtBytes } from '../api'

const s = computed(() => store.settings)
const ruleCount = computed(() => {
  const r = s.value?.bundle?.rules
  return Array.isArray(r) ? r.length : typeof r === 'number' ? r : store.rules.length
})
const hooks = computed(() => store.nodes.reduce((a, n) => Math.max(a, n.hooks_total), 0))
</script>

<template>
  <section class="card">
    <div class="hd"><h2>Agent</h2><span class="c">read-only</span></div>
    <div class="bd">
      <div v-if="!s" class="empty">Waiting for the backend…</div>
      <template v-else>
        <div class="setrow">
          <div><div class="t">Enforcement mode</div><div class="d">Detect observes only; Enforce kills at terminal states (pod cgroups only). Reflects the agent; not changeable here.</div></div>
          <div class="ctl"><div class="seg ro"><button disabled :class="{ on: !s.enforce }">Detect</button><button disabled :class="{ on: s.enforce }">Enforce</button></div></div>
        </div>
        <div class="setrow"><div><div class="t">Metrics endpoint</div><div class="d">Prometheus scrape target.</div></div><div class="ctl kv">{{ s.metrics_addr || '—' }}</div></div>
        <div class="setrow"><div><div class="t">Policy bundle</div><div class="d">Active compiled ruleset.</div></div><div class="ctl kv">{{ ruleCount }} rules<template v-if="hooks"> · {{ hooks }} hooks</template></div></div>
        <div class="setrow"><div><div class="t">Audit ring buffer</div><div class="d">Kernel → user-space event channel.</div></div><div class="ctl kv">{{ fmtBytes(s.audit_ring_bytes) }}<template v-if="store.overview"> · {{ store.overview.kpis.audit_dropped }} dropped</template></div></div>
        <div class="setrow"><div><div class="t">Kernel</div><div class="d">BTF + BPF LSM required.</div></div><div class="ctl kv">{{ s.kernel || '—' }}</div></div>
      </template>
    </div>
  </section>
</template>
