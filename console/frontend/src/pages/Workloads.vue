<script setup lang="ts">
import { computed, ref, onMounted, onBeforeUnmount } from 'vue'
import RowMenu from '../components/RowMenu.vue'
import { store, isAlerting, isKill, mute, unmute, inspectChain, type Workload } from '../api'

const nodes = computed(() => [...new Set(store.allWorkloads.map(w => w.node))].sort())
const alerting = computed(() => store.allWorkloads.filter(isAlerting).length)
const total = computed(() => store.allWorkloads.length)

const menu = ref<{ w: Workload; x: number; y: number } | null>(null)
const detail = ref<Workload | null>(null)

function toggle(ev: MouseEvent, w: Workload) {
  if (menu.value?.w.pod === w.pod) { menu.value = null; return }
  const r = (ev.currentTarget as HTMLElement).getBoundingClientRect()
  let top = r.bottom + 6
  if (top + 170 > window.innerHeight) top = r.top - 170
  menu.value = { w, x: Math.max(8, r.right - 190), y: top }
}
async function act(a: 'details' | 'chain' | 'copy' | 'mute') {
  const w = menu.value!.w
  menu.value = null
  if (a === 'details') detail.value = w
  else if (a === 'chain') inspectChain(w.pod)
  else if (a === 'copy') navigator.clipboard?.writeText(w.pod).catch(() => {})
  else {
    try { store.muted.includes(w.pod) ? await unmute(w.pod) : await mute(w.pod) } catch { store.offline = true }
  }
}
const close = () => { menu.value = null }
const key = (e: KeyboardEvent) => { if (e.key === 'Escape') { close(); detail.value = null } }
onMounted(() => { document.addEventListener('click', close); document.addEventListener('keydown', key); window.addEventListener('resize', close) })
onBeforeUnmount(() => { document.removeEventListener('click', close); document.removeEventListener('keydown', key); window.removeEventListener('resize', close) })
</script>

<template>
  <section class="card">
    <div class="hd"><h2>Workloads</h2><span class="c">{{ store.workloads.length }} of {{ total }}</span></div>
    <div class="toolbar">
      <button class="chip-f" :class="{ on: store.wlFilter === 'all' }" @click="store.wlFilter = 'all'">All <span class="n">{{ total }}</span></button>
      <button class="chip-f" :class="{ on: store.wlFilter === 'alerting' }" @click="store.wlFilter = 'alerting'">Alerting <span class="n">{{ alerting }}</span></button>
      <button class="chip-f" :class="{ on: store.wlFilter === 'quiet' }" @click="store.wlFilter = 'quiet'">Quiet <span class="n">{{ total - alerting }}</span></button>
      <button v-for="n in nodes" :key="n" class="chip-f" :class="{ on: store.wlFilter === n }" @click="store.wlFilter = n">{{ n }}</button>
      <div class="search">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3-3"/></svg>
        <input v-model="store.wlQ" placeholder="Search pod, comm, rule…">
      </div>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th>Pod</th><th>Namespace</th><th>Node</th><th>comm</th><th>Rule</th><th>State</th><th>Action</th><th></th></tr></thead>
        <tbody>
          <tr v-if="!store.workloads.length"><td colspan="8" class="empty">{{ total ? 'No workloads match this filter.' : 'No workloads reported yet.' }}</td></tr>
          <tr v-for="w in store.workloads" :key="w.pod + w.node">
            <td class="mono">{{ w.pod }}<span v-if="store.muted.includes(w.pod)" class="dim"> · muted</span></td>
            <td class="mono dim">{{ w.namespace }}</td><td class="mono dim">{{ w.node }}</td><td class="mono">{{ w.comm }}</td>
            <td class="mono"><span v-if="!w.rule || w.rule === '—'" class="dim">—</span><template v-else>{{ w.rule }}</template></td>
            <td><span class="st" :class="w.state">{{ w.state.replace('_', ' ') }}</span></td>
            <td><span class="act" :class="{ kill: isKill(w.action) }">{{ isKill(w.action) ? 'KILL' : 'observe' }}</span></td>
            <td class="right"><span class="amenu" :class="{ open: menu?.w.pod === w.pod }" @click.stop="toggle($event, w)">⋯</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>

  <RowMenu v-if="menu" :x="menu.x" :y="menu.y" :muted="store.muted.includes(menu.w.pod)" @action="act" />

  <div v-if="detail" class="modal-bg" @click="detail = null">
    <div class="modal" @click.stop>
      <div class="hd" style="display:flex;align-items:center;padding:11px 15px;border-bottom:1px solid var(--border)">
        <h2 style="margin:0;font-size:13px">{{ detail.pod }}</h2>
        <button class="btn" style="margin-left:auto" @click="detail = null">Close</button>
      </div>
      <div class="bd" style="padding:8px 15px 12px">
        <div class="kvrow"><span>Namespace</span><span class="mono">{{ detail.namespace }}</span></div>
        <div class="kvrow"><span>Node</span><span class="mono">{{ detail.node }}</span></div>
        <div class="kvrow"><span>comm</span><span class="mono">{{ detail.comm }}</span></div>
        <div class="kvrow"><span>Rule</span><span class="mono">{{ detail.rule || '—' }}</span></div>
        <div class="kvrow"><span>State</span><span class="st" :class="detail.state">{{ detail.state }}</span></div>
        <div class="kvrow"><span>Action</span><span class="mono">{{ detail.action }}</span></div>
      </div>
    </div>
  </div>
</template>
