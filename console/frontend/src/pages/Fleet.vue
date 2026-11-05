<script setup lang="ts">
import { computed } from 'vue'
import { store, clockNs, type FleetThreat } from '../api'
import StatStrip from '../components/StatStrip.vue'

const threats = computed(() => store.fleet ?? [])

const stats = computed(() => {
  const t = threats.value
  const widest = t.reduce((m, x) => (x.node_count > m.node_count ? x : m), { node_count: 0 } as FleetThreat)
  return [
    { label: 'Cross-node threats', value: t.length, hint: 'one signature on ≥2 agents' },
    { label: 'Widest', value: widest.node_count || 0, hint: widest.node_count ? widest.signature : '—', tone: 'crit' as const },
    { label: 'Spreading', value: t.filter(x => x.spreading).length, hint: 'reached new nodes over time', tone: 'warn' as const },
    { label: 'Contained', value: t.filter(x => x.killed > 0).length, hint: 'threats with a kill', tone: 'teal' as const },
  ]
})

// short image name without registry/digest, for the signature cell
const short = (t: FleetThreat) =>
  t.kind === 'rule' ? (t.rule || t.signature) : (t.image || t.signature).split('/').pop()!.split('@')[0]
</script>

<template>
  <div class="cols-stack">
    <p class="intro">
      <b>Fleet correlation</b> — the same threat active on more than one node at once: a compromised
      image (an <b>actor</b>) seen fleet-wide, or a <b>rule</b> firing across agents. Single-node
      incidents live under Blast radius; this is the coordinated / worm signal. Widest spread first.
    </p>

    <StatStrip :stats="stats" />

    <section class="card">
      <div class="hd"><h2>Cross-node threats</h2><span class="c">{{ threats.length }}</span></div>
      <div class="bd" v-if="!threats.length">
        <div class="empty">No threat has spanned more than one node in this range.</div>
      </div>
      <div class="scroll" v-else>
        <table>
          <thead>
            <tr>
              <th>Signature</th><th>Kind</th><th>Nodes</th><th>Incidents</th>
              <th>Outcomes</th><th>Node breakdown</th><th>First</th><th>Last</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(t, i) in threats" :key="i" class="campaign">
              <td>
                <span class="mono">{{ short(t) }}</span>
                <span v-if="t.spreading" class="mb spread">spreading</span>
              </td>
              <td><span class="kind" :class="t.kind">{{ t.kind }}</span></td>
              <td class="mono big">{{ t.node_count }}</td>
              <td class="mono">{{ t.incidents }}</td>
              <td>
                <span v-if="t.killed" class="mb kill">{{ t.killed }} killed</span>
                <span v-if="t.blocked" class="mb block">{{ t.blocked }} blocked</span>
                <span v-if="t.detected" class="mb det">{{ t.detected }} detected</span>
              </td>
              <td class="chips">
                <span v-for="n in t.nodes" :key="n.node" class="chip mono" :title="clockNs(n.first_ts_ns) + ' → ' + clockNs(n.last_ts_ns)">
                  {{ n.node }} · {{ n.incidents }}
                </span>
              </td>
              <td class="mono dim">{{ clockNs(t.first_ts_ns) }}</td>
              <td class="mono dim">{{ clockNs(t.last_ts_ns) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<style scoped>
.cols-stack { display:flex; flex-direction:column; gap:16px; }
.intro { margin:0; font-size:12.5px; color:var(--fg-2); }
.intro b { color:var(--fg); }
tbody tr.campaign { background:color-mix(in srgb, var(--crit) 7%, transparent); }
tbody tr.campaign:hover { background:color-mix(in srgb, var(--crit) 12%, transparent); }
tbody tr.campaign td:first-child { box-shadow:inset 3px 0 0 var(--crit); }
.big { font-weight:700; }
.kind { font-size:10.5px; font-weight:600; text-transform:uppercase; letter-spacing:.03em; padding:1px 7px; border-radius:999px; border:1px solid var(--border); color:var(--fg-2); background:var(--surface); }
.kind.actor { color:var(--crit); border-color:color-mix(in srgb, var(--crit) 45%, transparent); }
.mb { display:inline-block; font-size:10.5px; font-weight:600; padding:1px 7px; border-radius:999px; margin-right:5px; border:1px solid; }
.mb.kill { color:var(--crit); border-color:color-mix(in srgb, var(--crit) 45%, transparent); background:color-mix(in srgb, var(--crit) 12%, transparent); }
.mb.block { color:var(--orange); border-color:color-mix(in srgb, var(--orange) 45%, transparent); background:color-mix(in srgb, var(--orange) 12%, transparent); }
.mb.det { color:var(--muted); border-color:var(--border); background:var(--surface); }
.mb.spread { color:var(--orange); border-color:color-mix(in srgb, var(--orange) 45%, transparent); background:color-mix(in srgb, var(--orange) 12%, transparent); margin-left:8px; }
.chips { white-space:normal; max-width:320px; }
.chip { display:inline-block; font-size:10.5px; padding:1px 7px; border-radius:999px; margin:1px 4px 1px 0; background:var(--surface-2); border:1px solid var(--border); color:var(--fg-2); }
</style>
