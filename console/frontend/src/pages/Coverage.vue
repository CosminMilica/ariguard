<script setup lang="ts">
import { computed } from 'vue'
import { store, fmtNum, type CoverageHook } from '../api'

const cov = computed(() => store.coverage)
const hooks = computed(() => cov.value?.hooks ?? [])
const blindSpots = computed(() => hooks.value.filter(h => h.attached && !(h.rules?.length)).length)

const isBlind = (h: CoverageHook) => h.attached && !(h.rules?.length)
</script>

<template>
  <section class="card">
    <div class="hd">
      <h2>Detection coverage</h2>
      <span class="c">{{ cov ? cov.attached : 0 }}/{{ cov ? cov.total : 0 }} hooks · {{ blindSpots }} blind spots</span>
    </div>
    <div class="bd" v-if="!hooks.length"><div class="empty">No coverage data.</div></div>
    <div class="scroll" v-else>
      <table>
        <thead>
          <tr><th>Hook</th><th>Attached</th><th>Techniques</th><th>Rules</th><th class="right">Events</th></tr>
        </thead>
        <tbody>
          <tr v-for="(h, i) in hooks" :key="i" :class="{ blind: isBlind(h), off: !h.attached }">
            <td class="mono">{{ h.hook }}</td>
            <td>
              <span v-if="h.attached" class="chk">✓</span>
              <span v-else class="dash">—</span>
            </td>
            <td class="chips">
              <span v-for="t in h.techniques" :key="t" class="chip att mono">{{ t }}</span>
              <span v-if="!h.techniques?.length" class="dim">—</span>
            </td>
            <td class="chips">
              <template v-if="h.rules?.length">
                <span v-for="r in h.rules" :key="r" class="chip mono">{{ r }}</span>
              </template>
              <span v-else class="blind-tag">no rule</span>
            </td>
            <td class="right mono">{{ fmtNum(h.events) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
tbody tr.blind { background:color-mix(in srgb, var(--warn) 8%, transparent); }
tbody tr.blind td:first-child { box-shadow:inset 3px 0 0 var(--warn); }
tbody tr.off { opacity:.55; }
.chk { color:var(--ok); font-weight:700; }
.dash { color:var(--faint); }
.chips { white-space:normal; max-width:320px; }
.chip { display:inline-block; font-size:10.5px; padding:1px 7px; border-radius:999px; margin:1px 4px 1px 0; background:var(--surface-2); border:1px solid var(--border); color:var(--fg-2); }
.chip.att { color:var(--teal); border-color:color-mix(in srgb, var(--teal) 35%, transparent); }
.blind-tag { font-size:10.5px; font-weight:600; color:var(--warn); border:1px solid color-mix(in srgb, var(--warn) 45%, transparent); background:color-mix(in srgb, var(--warn) 12%, transparent); padding:1px 8px; border-radius:999px; }
</style>
