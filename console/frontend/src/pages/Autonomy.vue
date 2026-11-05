<script setup lang="ts">
import { computed } from 'vue'
import { store, clockNs, type AutoRule } from '../api'
import StatStrip from '../components/StatStrip.vue'

const a = computed(() => store.autonomy)
const rules = computed<AutoRule[]>(() => a.value?.rules ?? [])
const shadow = computed(() => rules.value.filter(r => r.mode === 'shadow'))

const stats = computed(() => {
  const s = shadow.value
  return [
    { label: 'Rules', value: rules.value.length, hint: 'in the live bundle' },
    { label: 'Shadow', value: s.length, hint: 'observe-only, proving themselves', tone: 'warn' as const },
    { label: 'Ready to promote', value: s.filter(r => r.status === 'ready').length, hint: 'enough hits, no FP', tone: 'teal' as const },
    { label: 'Flagged (FP)', value: s.filter(r => r.status === 'retire').length, hint: 'fired on a muted pod', tone: 'crit' as const },
  ]
})

const minDays = computed(() => a.value?.min_days ?? 7)
// progress toward promotion: days observed vs the window, capped at 100%.
const progress = (r: AutoRule) => Math.min(100, Math.round((r.days_observed / minDays.value) * 100))

const STATUS: Record<string, { text: string; cls: string }> = {
  enforcing: { text: 'enforcing', cls: 'ok' },
  ready: { text: 'ready to promote', cls: 'ready' },
  observing: { text: 'observing', cls: 'dim' },
  retire: { text: 'flagged (false positive)', cls: 'crit' },
}
</script>

<template>
  <section>
    <p class="intro">
      The autonomous loop mines new kill-chains (honeypot + community feeds), ships each as a
      <b>shadow</b> rule that only observes, and promotes it to <b>enforce</b> only once it has caught
      real attacks over {{ minDays }} days with <b>zero</b> hits on known-good (muted) workloads. A
      single false positive flags it. Nothing kills from a rule that has not earned it.
    </p>

    <StatStrip :stats="stats" />

    <div class="card">
      <div class="hd">
        <h2>Rules</h2>
        <span class="c" v-if="a?.policy_version">policy {{ a.policy_version.slice(0, 12) }} · updated {{ clockNs(a.policy_updated_ns) }}</span>
      </div>
      <div class="bd" v-if="!rules.length"><div class="empty">No rules reported yet.</div></div>
      <div class="scroll" v-else>
        <table>
          <thead>
            <tr><th>Rule</th><th>Source</th><th>Mode</th><th>Hits</th><th>Benign fires</th><th>Promotion</th><th>Status</th></tr>
          </thead>
          <tbody>
            <tr v-for="r in rules" :key="r.name" :class="{ sh: r.mode === 'shadow' }">
              <td class="mono">{{ r.name }}</td>
              <td><span class="tag" :class="r.source">{{ r.source }}</span></td>
              <td><span class="mode" :class="r.mode">{{ r.mode }}</span></td>
              <td class="mono">{{ r.hits }}</td>
              <td class="mono" :class="{ bad: r.benign_fires > 0 }">{{ r.benign_fires }}</td>
              <td class="prog">
                <template v-if="r.mode === 'shadow'">
                  <div class="bar" :class="{ full: r.status === 'ready', block: r.status === 'retire' }">
                    <span :style="{ width: progress(r) + '%' }"></span>
                  </div>
                  <span class="mono dim">{{ r.days_observed.toFixed(1) }}/{{ minDays }}d</span>
                </template>
                <span v-else class="dim">—</span>
              </td>
              <td><span :class="(STATUS[r.status] || STATUS.observing).cls">{{ (STATUS[r.status] || STATUS.observing).text }}</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>
</template>

<style scoped>
.intro { margin:0 0 14px; font-size:12.5px; color:var(--fg-2); }
.intro b { color:var(--fg); }
tbody tr.sh td:first-child { box-shadow:inset 3px 0 0 var(--orange); }
.tag { font-size:10.5px; padding:1px 7px; border-radius:999px; border:1px solid var(--border); color:var(--muted); background:var(--surface-2); }
.tag.auto { border-color:var(--teal-dim); color:var(--teal); }
.mode { font-size:11px; font-weight:600; }
.mode.shadow { color:var(--orange); } .mode.enforce { color:var(--crit); }
.bad { color:var(--crit); font-weight:600; }
.prog { white-space:nowrap; }
.prog .bar { display:inline-block; width:70px; height:6px; border-radius:3px; background:var(--surface-2); overflow:hidden; vertical-align:middle; margin-right:8px; }
.prog .bar span { display:block; height:100%; background:var(--orange); }
.prog .bar.full span { background:var(--teal); }
.prog .bar.block span { background:var(--crit); }
.ok { color:var(--muted); } .ready { color:var(--teal); font-weight:600; } .crit { color:var(--crit); font-weight:600; }
</style>
