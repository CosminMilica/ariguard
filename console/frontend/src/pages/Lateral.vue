<script setup lang="ts">
import { computed, ref } from 'vue'
import { store, clockNs, openChainModal, type Edge } from '../api'

// Observed network pivots (F2): real pod→pod connections, not image-correlation inference.
const edges = computed<Edge[]>(() => store.edges ?? [])
const crossNsEdges = computed(() => edges.value.filter(e => e.cross_ns).length)
const crossOnly = ref(false)
const shown = computed(() => crossOnly.value ? edges.value.filter(e => e.cross_ns) : edges.value)

const shortNs = (s: string) => (s.length > 20 ? s.slice(0, 19) + '…' : s)

// Well-known destination ports, labelled for context.
const PORTS: Record<number, string> = {
  22: 'ssh', 53: 'dns', 80: 'http', 443: 'https', 2379: 'etcd', 3306: 'mysql',
  5432: 'postgres', 6379: 'redis', 8080: 'http', 9092: 'kafka', 10250: 'kubelet', 27017: 'mongo',
}
const portLabel = (p: number) => (PORTS[p] ? `${p} ${PORTS[p]}` : `${p}`)

function chips(list: string[]) {
  const a = list ?? []
  return { shown: a.slice(0, 3), rest: a.length - Math.min(a.length, 3) }
}
</script>

<template>
  <section class="card">
    <div class="hd">
      <h2>Network pivots</h2>
      <span class="c">{{ edges.length }} edges · {{ crossNsEdges }} cross-namespace</span>
    </div>

    <p class="intro">
      Observed lateral movement — real <b>pod → pod</b> connections the agent saw (a compromised pod's
      <code>connect</code> whose destination IP resolved to another pod). Cross-namespace pivots first;
      click a row to inspect the source pod's chain.
    </p>

    <div class="toolbar" v-if="edges.length">
      <button class="chip-f" :class="{ on: crossOnly }" @click="crossOnly = !crossOnly">Cross-namespace only</button>
    </div>

    <div class="bd" v-if="!edges.length">
      <div class="empty">
        No pod-to-pod pivots observed in this range.<br>
        <span class="faint">A pivot appears when a compromised pod connects to another pod's IP (e.g. an
        internal service). External C2 destinations stay on the Actors view.</span>
      </div>
    </div>

    <div class="scroll" v-else>
      <table>
        <thead>
          <tr><th>Pivot (source → destination)</th><th>Reach</th><th>Conns</th><th>Ports</th><th>Rules</th><th>Last</th></tr>
        </thead>
        <tbody>
          <tr v-for="(e, i) in shown" :key="i" class="clickable" :class="{ mover: e.cross_ns }"
            @click="openChainModal(e.src_pod)">
            <td class="pivot">
              <span class="mono">{{ e.src_pod }}</span><span class="dim"> · {{ shortNs(e.src_namespace) }}</span>
              <span class="arr">→</span>
              <span class="mono">{{ e.dst_pod }}</span><span class="dim"> · {{ shortNs(e.dst_namespace) }}</span>
            </td>
            <td><span class="chip" :class="e.cross_ns ? 'hit' : ''">{{ e.cross_ns ? 'cross-ns' : 'same-ns' }}</span></td>
            <td class="mono">{{ e.count }}</td>
            <td class="chips"><span v-for="p in e.ports" :key="p" class="chip mono">{{ portLabel(p) }}</span></td>
            <td class="chips">
              <span v-for="r in chips(e.rules).shown" :key="r" class="chip mono">{{ r }}</span>
              <span v-if="chips(e.rules).rest > 0" class="chip more">+{{ chips(e.rules).rest }}</span>
            </td>
            <td class="mono dim">{{ clockNs(e.last_ts_ns) }}</td>
          </tr>
          <tr v-if="!shown.length"><td colspan="6" class="empty">No cross-namespace pivots in this range.</td></tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
.intro { margin:0; padding:12px 15px; border-bottom:1px solid var(--border); font-size:12.5px; color:var(--fg-2); }
.intro b { color:var(--fg); }
.intro code { font-family:var(--mono); font-size:11.5px; color:var(--fg-2); background:var(--surface-2); padding:1px 5px; border-radius:4px; }

tbody tr.mover td:first-child { box-shadow:inset 3px 0 0 var(--teal-dim); }
tbody tr.clickable { cursor:pointer; }
tbody tr.clickable:hover { background:color-mix(in srgb, var(--teal) 8%, transparent); }

td.pivot { white-space:nowrap; }
.pivot .arr { color:var(--teal); margin:0 9px; font-family:var(--mono); }
.chips { white-space:normal; max-width:220px; }
.chip { display:inline-block; font-size:10.5px; padding:1px 7px; border-radius:999px; margin:1px 2px 1px 0; background:var(--surface-2); border:1px solid var(--border); color:var(--fg-2); }
.chip.hit { border-color:var(--teal-dim); color:var(--fg); background:color-mix(in srgb, var(--teal) 16%, var(--surface-2)); }
.chip.more { color:var(--faint); }
.dim { color:var(--faint); }
.faint { color:var(--faint); font-size:11.5px; }
</style>
