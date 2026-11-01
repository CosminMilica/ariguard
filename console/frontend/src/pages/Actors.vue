<script setup lang="ts">
import { computed } from 'vue'
import { store, clockNs } from '../api'

const actors = computed(() => store.actors ?? [])

const wide = (pods: number, namespaces: number) => pods >= 3 || namespaces >= 2

function shortDigest(imageId: string): string {
  const s = (imageId || '').trim()
  const at = s.indexOf('@')
  const hex = (at >= 0 ? s.slice(at + 1) : s).replace(/^sha256:/, '')
  return hex ? hex.slice(-12) : ''
}

function chips(list: string[]) {
  const a = list ?? []
  const shown = a.slice(0, 5)
  return { shown, rest: a.length - shown.length }
}
</script>

<template>
  <section class="card">
    <div class="hd">
      <h2>Actors</h2>
      <span class="c">{{ actors.length }} actors · widest spread first</span>
    </div>
    <div class="bd" v-if="!actors.length"><div class="empty">No actors in this range.</div></div>
    <div class="scroll" v-else>
      <table>
        <thead>
          <tr>
            <th>Image</th><th>Incidents</th><th>Pods</th><th>Namespaces</th><th>Nodes</th>
            <th>Rules</th><th>Comms</th><th>Outcomes</th><th>First</th><th>Last</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(a, i) in actors" :key="i" :class="{ actor: wide(a.pods, a.namespaces) }">
            <td :title="a.image_id">
              <div>{{ a.image }}</div>
              <div class="mono dim digest">{{ shortDigest(a.image_id) }}</div>
            </td>
            <td class="mono">{{ a.incidents }}</td>
            <td class="mono">{{ a.pods }}</td>
            <td class="mono">{{ a.namespaces }}</td>
            <td class="mono">{{ a.nodes }}</td>
            <td class="chips">
              <span v-for="r in chips(a.rules).shown" :key="r" class="chip mono">{{ r }}</span>
              <span v-if="chips(a.rules).rest > 0" class="chip more">+{{ chips(a.rules).rest }}</span>
            </td>
            <td class="chips">
              <span v-for="c in chips(a.comms).shown" :key="c" class="chip mono">{{ c }}</span>
              <span v-if="chips(a.comms).rest > 0" class="chip more">+{{ chips(a.comms).rest }}</span>
            </td>
            <td>
              <span v-if="a.killed" class="act kill">{{ a.killed }} killed</span>
              <span v-if="a.blocked" class="act deny">{{ a.blocked }} blocked</span>
              <span v-if="a.detected" class="act">{{ a.detected }} detected</span>
            </td>
            <td class="mono dim">{{ clockNs(a.first_ts_ns) }}</td>
            <td class="mono dim">{{ clockNs(a.last_ts_ns) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
tbody tr.actor { background:color-mix(in srgb, var(--crit) 7%, transparent); }
tbody tr.actor:hover { background:color-mix(in srgb, var(--crit) 12%, transparent); }
tbody tr.actor td:first-child { box-shadow:inset 3px 0 0 var(--crit); }
.digest { font-size:10.5px; margin-top:2px; }
.act { margin-right:8px; font-size:11.5px; }
.chips { white-space:normal; max-width:260px; }
.chip { display:inline-block; font-size:10.5px; padding:1px 7px; border-radius:999px; margin:1px 4px 1px 0; background:var(--surface-2); border:1px solid var(--border); color:var(--fg-2); }
.chip.more { color:var(--faint); }
</style>
