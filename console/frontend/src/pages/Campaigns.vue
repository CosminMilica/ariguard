<script setup lang="ts">
import { computed } from 'vue'
import { store, clockNs, type CampaignRule, type CampaignNs } from '../api'

const byRule = computed(() => store.campaigns?.by_rule ?? [])
const byNs = computed(() => store.campaigns?.by_namespace ?? [])

const wide = (pods: number, spread: number) => pods >= 3 || spread >= 2

function chips(list: string[]) {
  const arr = list ?? []
  const shown = arr.slice(0, 5)
  const rest = arr.length - shown.length
  return { shown, rest }
}
</script>

<template>
  <div class="cols-stack">
    <section class="card">
      <div class="hd"><h2>Blast radius — by rule</h2><span class="c">{{ byRule.length }} rules</span></div>
      <div class="bd" v-if="!byRule.length"><div class="empty">No campaigns in this range.</div></div>
      <div class="scroll" v-else>
        <table>
          <thead>
            <tr>
              <th>Rule</th><th>Incidents</th><th>Pods</th><th>Namespaces</th><th>Nodes</th>
              <th>Outcomes</th><th>Spread</th><th>First</th><th>Last</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(r, i) in byRule" :key="i" :class="{ campaign: wide(r.pods, r.namespaces) }">
              <td>{{ r.rule }}</td>
              <td class="mono">{{ r.incidents }}</td>
              <td class="mono">{{ r.pods }}</td>
              <td class="mono">{{ r.namespaces }}</td>
              <td class="mono">{{ r.nodes }}</td>
              <td>
                <span v-if="r.killed" class="mb kill">{{ r.killed }} killed</span>
                <span v-if="r.blocked" class="mb block">{{ r.blocked }} blocked</span>
                <span v-if="r.detected" class="mb det">{{ r.detected }} detected</span>
              </td>
              <td class="chips">
                <span v-for="n in chips(r.affected_namespaces).shown" :key="n" class="chip mono">{{ n }}</span>
                <span v-if="chips(r.affected_namespaces).rest > 0" class="chip more">+{{ chips(r.affected_namespaces).rest }}</span>
              </td>
              <td class="mono dim">{{ clockNs(r.first_ts_ns) }}</td>
              <td class="mono dim">{{ clockNs(r.last_ts_ns) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <div class="hd"><h2>Blast radius — by namespace</h2><span class="c">{{ byNs.length }} namespaces</span></div>
      <div class="bd" v-if="!byNs.length"><div class="empty">No campaigns in this range.</div></div>
      <div class="scroll" v-else>
        <table>
          <thead>
            <tr>
              <th>Namespace</th><th>Incidents</th><th>Pods</th><th>Rules</th><th>Nodes</th>
              <th>Outcomes</th><th>Rules hit</th><th>First</th><th>Last</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(n, i) in byNs" :key="i" :class="{ campaign: wide(n.pods, n.rules) }">
              <td class="mono">{{ n.namespace }}</td>
              <td class="mono">{{ n.incidents }}</td>
              <td class="mono">{{ n.pods }}</td>
              <td class="mono">{{ n.rules }}</td>
              <td class="mono">{{ n.nodes }}</td>
              <td>
                <span v-if="n.killed" class="mb kill">{{ n.killed }} killed</span>
                <span v-if="n.blocked" class="mb block">{{ n.blocked }} blocked</span>
                <span v-if="n.detected" class="mb det">{{ n.detected }} detected</span>
              </td>
              <td class="chips">
                <span v-for="r in chips(n.affected_rules).shown" :key="r" class="chip mono">{{ r }}</span>
                <span v-if="chips(n.affected_rules).rest > 0" class="chip more">+{{ chips(n.affected_rules).rest }}</span>
              </td>
              <td class="mono dim">{{ clockNs(n.first_ts_ns) }}</td>
              <td class="mono dim">{{ clockNs(n.last_ts_ns) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<style scoped>
.cols-stack { display:flex; flex-direction:column; gap:16px; }
tbody tr.campaign { background:color-mix(in srgb, var(--crit) 7%, transparent); }
tbody tr.campaign:hover { background:color-mix(in srgb, var(--crit) 12%, transparent); }
tbody tr.campaign td:first-child { box-shadow:inset 3px 0 0 var(--crit); }
.mb { display:inline-block; font-size:10.5px; font-weight:600; padding:1px 7px; border-radius:999px; margin-right:5px; border:1px solid; }
.mb.kill { color:var(--crit); border-color:color-mix(in srgb, var(--crit) 45%, transparent); background:color-mix(in srgb, var(--crit) 12%, transparent); }
.mb.block { color:var(--orange); border-color:color-mix(in srgb, var(--orange) 45%, transparent); background:color-mix(in srgb, var(--orange) 12%, transparent); }
.mb.det { color:var(--muted); border-color:var(--border); background:var(--surface); }
.chips { white-space:normal; max-width:280px; }
.chip { display:inline-block; font-size:10.5px; padding:1px 7px; border-radius:999px; margin:1px 4px 1px 0; background:var(--surface-2); border:1px solid var(--border); color:var(--fg-2); }
.chip.more { color:var(--faint); }
</style>
