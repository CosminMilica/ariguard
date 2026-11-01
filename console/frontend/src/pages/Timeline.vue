<script setup lang="ts">
import { computed, ref } from 'vue'
import { store, clockNs, actLabel, procLabel, sevKey, pad, toMs, openChainModal, shortImage, type AEvent } from '../api'

const q = ref('')
const sev = ref('all')
const sevs = [['all', 'All'], ['crit', 'Critical'], ['mid', 'Escalating'], ['warn', 'Suspicious'], ['info', 'Info']]

const minuteLabel = (ns: number) => {
  const d = new Date(toMs(ns))
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`
}

const filtered = computed(() => {
  const needle = q.value.trim().toLowerCase()
  const s = sev.value
  const out: AEvent[] = []
  for (const e of store.allEvents) {
    if (s !== 'all' && sevKey(e.severity) !== s) continue
    if (needle && !`${e.pod}${e.rule}${e.node}${e.namespace}${e.event}${e.comm ?? ''}`.toLowerCase().includes(needle)) continue
    out.push(e)
    if (out.length >= 500) break
  }
  return out
})

// Group the (already time-ordered, newest first) events by minute for a single scannable axis.
const groups = computed(() => {
  const g: { minute: string; events: AEvent[] }[] = []
  let cur: { minute: string; events: AEvent[] } | null = null
  for (const e of filtered.value) {
    const m = minuteLabel(e.ts_ns)
    if (!cur || cur.minute !== m) { cur = { minute: m, events: [] }; g.push(cur) }
    cur.events.push(e)
  }
  return g
})
</script>

<template>
  <section class="card">
    <div class="hd"><h2>Timeline</h2><span class="c">{{ filtered.length }} events</span></div>
    <div class="toolbar">
      <button v-for="c in sevs" :key="c[0]" class="chip-f" :class="{ on: sev === c[0] }" @click="sev = c[0]">{{ c[1] }}</button>
      <div class="search">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3-3"/></svg>
        <input v-model="q" placeholder="Search pod, rule, node, process…">
      </div>
    </div>
    <div class="bd">
      <div v-if="!groups.length" class="empty">No events in this range.</div>
      <div v-else class="tl">
        <div v-for="g in groups" :key="g.minute" class="tl-group">
          <div class="tl-minute mono">{{ g.minute }}</div>
          <div class="tl-rows">
            <div v-for="(e, i) in g.events" :key="e.ts_ns + e.pod + i" class="tl-row" :class="sevKey(e.severity)" @click="openChainModal(e.pod)">
              <span class="tl-time mono dim">{{ clockNs(e.ts_ns) }}</span>
              <span class="tl-sev" :class="sevKey(e.severity)"></span>
              <span class="tl-act" :class="actLabel(e.action, e.enforced).cls">{{ actLabel(e.action, e.enforced).text }}</span>
              <span class="tl-rule">{{ e.rule }}</span>
              <span class="tl-proc mono">{{ procLabel(e.comm, e.pid) || '—' }}</span>
              <span class="tl-hook mono">{{ e.hook || '—' }}</span>
              <span v-if="e.image" class="tl-img mono dim" :title="e.image">{{ shortImage(e.image) }}</span>
              <span class="tl-ctx mono dim">{{ e.pod }} · {{ e.namespace }} · {{ e.node }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.tl { display:flex; flex-direction:column; }
.tl-group { display:grid; grid-template-columns:56px 1fr; gap:10px; padding:6px 0; border-bottom:1px solid var(--border-2); }
.tl-group:last-child { border-bottom:0; }
.tl-minute { font-size:12px; color:var(--teal); padding-top:7px; position:sticky; }
.tl-rows { display:flex; flex-direction:column; min-width:0; }
.tl-row { display:flex; align-items:center; gap:10px; padding:5px 6px; border-radius:6px; cursor:pointer; font-size:12.5px; white-space:nowrap; overflow:hidden; }
.tl-row:hover { background:var(--hover); }
.tl-time { font-size:11.5px; flex:none; }
.tl-sev { width:3px; height:16px; border-radius:2px; background:var(--faint); flex:none; }
.tl-sev.crit { background:var(--crit); }
.tl-sev.mid { background:var(--mid); }
.tl-sev.warn { background:var(--warn); }
.tl-act { flex:none; min-width:64px; font-size:11.5px; }
.tl-rule { flex:none; font-weight:550; }
.tl-proc { color:var(--fg-2); flex:none; }
.tl-hook { color:var(--teal); flex:none; }
.tl-img { flex:none; font-size:11px; color:var(--fg-2); background:var(--hover); padding:0 5px; border-radius:4px; }
.tl-ctx { min-width:0; overflow:hidden; text-overflow:ellipsis; margin-left:auto; }
</style>
