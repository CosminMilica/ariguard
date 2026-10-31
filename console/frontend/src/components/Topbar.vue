<script setup lang="ts">
import { computed, ref, onMounted, onBeforeUnmount } from 'vue'
import { store, clearWindow, hasWindow, clock, type Range } from '../api'

const open = ref(false)
const ranges: Range[] = ['15m', '1h', '24h']
const root = ref<HTMLElement>()

const meta = computed(() => {
  const w = store.allWorkloads.length, n = store.nodes.length
  const m: Record<string, [string, string]> = {
    overview: ['Overview', `${n} nodes · ${w} workloads monitored`],
    workloads: ['Workloads', `${w} pods · live cgroup FSM state (current)`],
    events: ['Events', 'terminal states & mitigations'],
    incidents: ['Incidents', 'attack history · what happened'],
    rules: ['Rules', `compiled bundle · ${store.rules.length} rules`],
    nodes: ['Nodes', `DaemonSet · ${n} agents`],
    settings: ['Settings', 'agent configuration'],
  }
  return m[store.page]
})
const enforce = computed(() => !!store.settings?.enforce)

const winLabel = computed(() => {
  if (!hasWindow()) return ''
  const f = (ms: number) => { const d = new Date(ms); return `${d.getMonth() + 1}/${d.getDate()} ${clock(ms)}` }
  return `${f(store.customFrom)} → ${f(store.customTo)}`
})
function pick(r: Range) { clearWindow(); store.range = r; open.value = false }
function onDoc(e: MouseEvent) { if (root.value && !root.value.contains(e.target as Node)) open.value = false }
onMounted(() => document.addEventListener('click', onDoc))
onBeforeUnmount(() => document.removeEventListener('click', onDoc))
</script>

<template>
  <div class="topbar">
    <div>
      <h1>{{ meta[0] }}</h1>
      <div class="sub">{{ meta[1] }}</div>
    </div>
    <div class="spacer"></div>
    <span v-if="store.offline" class="offline">backend offline</span>
    <span v-if="winLabel" class="winsel mono">{{ winLabel }} <button class="btn" @click="clearWindow()">✕ reset</button></span>
    <div class="range" ref="root">
      <button class="btn" @click="open = !open">{{ winLabel ? 'Custom' : 'Last ' + store.range }} ▾</button>
      <div v-if="open" class="menu" style="position:absolute; right:0; top:34px; min-width:120px">
        <button v-for="r in ranges" :key="r" @click="pick(r)">Last {{ r }}</button>
      </div>
    </div>
    <span v-if="store.settings" class="badge static" :class="enforce ? 'enforce' : 'detect'">
      <span class="dot"></span> {{ enforce ? 'Enforce' : 'Detect' }}
    </span>
  </div>
</template>
