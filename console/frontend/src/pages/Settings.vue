<script setup lang="ts">
import { computed, ref } from 'vue'
import { store, fmtBytes, observeNamespace, unobserveNamespace, learnNamespace, unlearnNamespace, setMode } from '../api'

const s = computed(() => store.settings)
const ruleCount = computed(() => {
  const r = s.value?.bundle?.rules
  return Array.isArray(r) ? r.length : typeof r === 'number' ? r : store.rules.length
})
const hooks = computed(() => store.nodes.reduce((a, n) => Math.max(a, n.hooks_total), 0))

// The toggle reflects the operator's chosen mode immediately; the agents converge within a poll
// interval. desiredEnforce falls back to the reported agent mode until a mode has been set.
const desiredEnforce = computed(() => (store.mode.set ? store.mode.enforce : !!s.value?.enforce))
const applying = computed(() => store.mode.set && !!s.value && store.mode.enforce !== s.value.enforce)

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

// Learn-mode: namespaces whose pods emit full-syscall traces for novel-chain mining. Opt-in per
// namespace; the same namespace universe as enforcement (workloads plus any already opted in).
const learnNs = computed(() => {
  const set = new Set<string>(store.learnNamespaces)
  for (const w of store.allWorkloads) if (w.namespace) set.add(w.namespace)
  return [...set].sort()
})
const isLearning = (ns: string) => store.learnNamespaces.includes(ns)
const newLearnNs = ref('')
function addLearnNs() {
  const ns = newLearnNs.value.trim()
  if (ns && !isLearning(ns)) learnNamespace(ns)
  newLearnNs.value = ''
}
</script>

<template>
  <section class="card">
    <div class="hd"><h2>Agent</h2></div>
    <div class="bd">
      <div v-if="!s" class="empty">Waiting for the backend…</div>
      <template v-else>
        <div class="setrow">
          <div><div class="t">Enforcement mode</div><div class="d">Detect observes only; Enforce kills at terminal states (pod cgroups only). Sets the fleet mode on the control plane; agents hot-swap it within ~10s, no restart.<span v-if="applying" class="applying"> · applying to agents…</span></div></div>
          <div class="ctl"><div class="seg"><button :class="{ on: !desiredEnforce }" @click="setMode(false)">Detect</button><button :class="{ on: desiredEnforce }" @click="setMode(true)">Enforce</button></div></div>
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

  <section class="card">
    <div class="hd"><h2>Learn-mode namespaces</h2><span class="c">{{ store.learnNamespaces.length }} learning</span></div>
    <div class="bd">
      <div class="note">On, the agent emits full-syscall traces from pods in a namespace to the console, so the rule-generation loop mines novel attack chains from real production traffic and gates them against a real benign baseline. Opt-in per namespace; detection is unchanged, this only adds the raw trace stream (small per-syscall overhead on the opted-in pods). Agents must run with <span class="mono">--learn</span>.</div>
      <div v-if="!learnNs.length" class="empty">No namespaces yet.</div>
      <div v-for="ns in learnNs" :key="ns" class="setrow">
        <div><div class="t mono">{{ ns }}</div></div>
        <div class="ctl">
          <div class="seg">
            <button :class="{ on: isLearning(ns) }" @click="learnNamespace(ns)">Learn</button>
            <button :class="{ on: !isLearning(ns) }" @click="unlearnNamespace(ns)">Off</button>
          </div>
        </div>
      </div>
      <div class="setrow">
        <div><div class="d">Add a namespace that has no workloads yet.</div></div>
        <div class="ctl add">
          <input v-model="newLearnNs" placeholder="namespace" @keyup.enter="addLearnNs" />
          <button class="btn" @click="addLearnNs">Add as Learn</button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.note { font-size: 12px; color: var(--muted); margin-bottom: 10px; line-height: 1.4; }
.applying { color: var(--teal); }
.ctl.add { display: flex; gap: 6px; }
.ctl.add input { background: var(--surface); border: 1px solid var(--border); color: inherit; border-radius: 6px; padding: 4px 8px; font-size: 12px; }
</style>
