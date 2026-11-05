<script setup lang="ts">
import { computed, ref } from 'vue'
import { store, fmtBytes, observeNamespace, unobserveNamespace } from '../api'

const s = computed(() => store.settings)
const ruleCount = computed(() => {
  const r = s.value?.bundle?.rules
  return Array.isArray(r) ? r.length : typeof r === 'number' ? r : store.rules.length
})
const hooks = computed(() => store.nodes.reduce((a, n) => Math.max(a, n.hooks_total), 0))

// Per-namespace enforcement: namespaces seen on workloads plus any already observe-only, sorted.
const namespaces = computed(() => {
  const set = new Set<string>(store.observeNamespaces)
  for (const w of store.allWorkloads) if (w.namespace) set.add(w.namespace)
  return [...set].sort()
})
const isObserved = (ns: string) => store.observeNamespaces.includes(ns)
const newNs = ref('')
function addNs() {
  const ns = newNs.value.trim()
  if (ns && !isObserved(ns)) observeNamespace(ns)
  newNs.value = ''
}
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

  <section class="card">
    <div class="hd"><h2>Namespace enforcement</h2><span class="c">{{ store.observeNamespaces.length }} observe-only</span></div>
    <div class="bd">
      <div class="note">Detect (observe-only) stops the agent killing or quarantining pods in a namespace, while their events still count as attacks — so a discovery honeypot keeps running and its mined rules still promote. Everything else stays on the fleet's Enforce mode.</div>
      <div v-if="!namespaces.length" class="empty">No namespaces yet.</div>
      <div v-for="ns in namespaces" :key="ns" class="setrow">
        <div><div class="t mono">{{ ns }}</div></div>
        <div class="ctl">
          <div class="seg">
            <button :class="{ on: isObserved(ns) }" @click="observeNamespace(ns)">Detect</button>
            <button :class="{ on: !isObserved(ns) }" @click="unobserveNamespace(ns)">Enforce</button>
          </div>
        </div>
      </div>
      <div class="setrow">
        <div><div class="d">Mark a namespace that has no workloads yet (e.g. a honeypot before it starts).</div></div>
        <div class="ctl add">
          <input v-model="newNs" placeholder="namespace" @keyup.enter="addNs" />
          <button class="btn" @click="addNs">Add as Detect</button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.note { font-size: 12px; color: var(--muted); margin-bottom: 10px; line-height: 1.4; }
.ctl.add { display: flex; gap: 6px; }
.ctl.add input { background: var(--surface); border: 1px solid var(--border); color: inherit; border-radius: 6px; padding: 4px 8px; font-size: 12px; }
</style>
