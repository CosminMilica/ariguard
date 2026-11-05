<script setup lang="ts">
import { computed, ref } from 'vue'
import { store, clockNs, openChainModal, type Actor } from '../api'
import StatStrip from '../components/StatStrip.vue'

const actors = computed<Actor[]>(() => store.actors ?? [])
const maxPods = computed(() => Math.max(1, ...actors.value.map(a => a.pods)))

const stats = computed(() => {
  const a = actors.value
  const widest = a.reduce((m, x) => (x.pods > m.pods ? x : m), { pods: 0 } as Actor)
  return [
    { label: 'Actors', value: a.length, hint: 'distinct malicious images' },
    { label: 'Widest spread', value: widest.pods || 0, hint: widest.pods ? workload(widest) : '—', tone: 'crit' as const },
    { label: 'Contained', value: a.filter(x => x.killed > 0).length, hint: 'actor had a kill', tone: 'teal' as const },
    { label: 'Cross-namespace', value: a.filter(x => x.namespaces >= 2).length, hint: 'spans ≥2 namespaces', tone: 'warn' as const },
  ]
})

// The human name for an actor: its workload, else app label, else the image.
function workload(a: Actor): string {
  return a.owners?.[0] || a.apps?.[0] || a.image || '—'
}
function shortDigest(imageId: string): string {
  const s = (imageId || '').trim()
  const at = s.indexOf('@')
  const hex = (at >= 0 ? s.slice(at + 1) : s).replace(/^sha256:/, '')
  return hex ? hex.slice(-12) : ''
}

const open = ref<number | null>(null)
const toggle = (i: number) => { open.value = open.value === i ? null : i }
</script>

<template>
  <section>
    <p class="intro">
      An <b>actor</b> is a container image behaving maliciously, grouped across every pod and namespace
      it ran in (inference by image digest). Widest spread first — the most likely fleet-wide compromise.
      Click a row to see its workloads, C2 destinations and the pods to inspect.
    </p>

    <StatStrip :stats="stats" />

    <div class="card">
      <div class="hd"><h2>Actors</h2><span class="c">{{ actors.length }} · widest spread first</span></div>
      <div class="bd" v-if="!actors.length"><div class="empty">No actors in this range.</div></div>
      <div class="scroll" v-else>
        <table>
          <thead>
            <tr><th>Workload</th><th>Spread</th><th>Incidents</th><th>Outcomes</th><th>C2</th><th>Last</th></tr>
          </thead>
          <tbody>
            <template v-for="(a, i) in actors" :key="i">
              <tr class="clickable" :class="{ actor: a.pods >= 3 || a.namespaces >= 2, open: open === i }" @click="toggle(i)">
                <td>
                  <div class="wl">{{ workload(a) }}<span v-if="a.shared_c2?.length" class="linked" title="Shares a C2 destination with another image — likely the same campaign">linked</span></div>
                  <div class="mono dim sub">{{ a.image }}</div>
                </td>
                <td class="spread">
                  <div class="bar"><span :style="{ width: Math.round((a.pods / maxPods) * 100) + '%' }"></span></div>
                  <span class="mono dim">{{ a.pods }}p · {{ a.namespaces }}ns</span>
                </td>
                <td class="mono">{{ a.incidents }}</td>
                <td class="out">
                  <span v-if="a.killed" class="act kill">{{ a.killed }} killed</span>
                  <span v-if="a.blocked" class="act deny">{{ a.blocked }} blocked</span>
                  <span v-if="a.detected" class="act det">{{ a.detected }} detected</span>
                </td>
                <td class="mono">{{ a.dst_ips?.length || 0 }}</td>
                <td class="mono dim">{{ clockNs(a.last_ts_ns) }}</td>
              </tr>
              <tr v-if="open === i" class="detail">
                <td colspan="6">
                  <div class="dgrid">
                    <div class="dcol" v-if="a.image_id">
                      <div class="dh">Image</div>
                      <div class="mono">{{ a.image }}</div>
                      <div class="mono dim">{{ shortDigest(a.image_id) }}</div>
                    </div>
                    <div class="dcol" v-if="a.rules?.length">
                      <div class="dh">Rules</div>
                      <span v-for="r in a.rules" :key="r" class="chip mono">{{ r }}</span>
                    </div>
                    <div class="dcol" v-if="a.comms?.length">
                      <div class="dh">Processes</div>
                      <span v-for="c in a.comms" :key="c" class="chip mono">{{ c }}</span>
                    </div>
                    <div class="dcol" v-if="a.dst_ips?.length">
                      <div class="dh">C2 destinations<span v-if="a.shared_c2?.length" class="dh-note"> · shared = same IP as another image</span></div>
                      <span v-for="d in a.dst_ips" :key="d" class="chip mono c2" :class="{ shared: a.shared_c2?.includes(d) }" :title="a.shared_c2?.includes(d) ? 'Shared with another image' : ''">{{ d }}</span>
                    </div>
                    <div class="dcol" v-if="a.affected_namespaces?.length">
                      <div class="dh">Namespaces</div>
                      <span v-for="n in a.affected_namespaces" :key="n" class="chip mono">{{ n }}</span>
                    </div>
                  </div>
                  <div class="pods" v-if="a.affected_pods?.length">
                    <div class="dh">Pods — click to inspect the chain</div>
                    <span v-for="p in a.affected_pods" :key="p" class="chip mono pod" @click.stop="openChainModal(p)">{{ p }}</span>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </div>
  </section>
</template>

<style scoped>
.intro { margin:0 0 14px; font-size:12.5px; color:var(--fg-2); }
.intro b { color:var(--fg); }
tbody tr.actor td:first-child { box-shadow:inset 3px 0 0 var(--crit); }
tbody tr.clickable { cursor:pointer; }
tbody tr.clickable:hover { background:color-mix(in srgb, var(--crit) 7%, transparent); }
tbody tr.open { background:color-mix(in srgb, var(--crit) 9%, transparent); }
.wl { font-weight:550; }
.sub { font-size:10.5px; margin-top:2px; }
.spread { white-space:nowrap; }
.spread .bar { display:inline-block; width:70px; height:6px; border-radius:3px; background:var(--surface-2); overflow:hidden; vertical-align:middle; margin-right:8px; }
.spread .bar span { display:block; height:100%; background:var(--crit); }
.act { margin-right:7px; font-size:11px; }
.act.kill { color:var(--crit); } .act.deny { color:var(--orange); } .act.det { color:var(--muted); }
tr.detail > td { background:var(--bg-2); padding:14px 15px; }
.dgrid { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:14px 18px; }
.dh { font-size:10px; text-transform:uppercase; letter-spacing:.4px; color:var(--faint); margin-bottom:6px; }
.dcol .mono + .mono { margin-top:2px; }
.pods { margin-top:14px; }
.chip { display:inline-block; font-size:10.5px; padding:1px 7px; border-radius:999px; margin:2px 5px 2px 0; background:var(--surface-2); border:1px solid var(--border); color:var(--fg-2); }
.chip.c2 { border-color:color-mix(in srgb, var(--orange) 40%, transparent); color:var(--orange); }
.chip.c2.shared { border-color:color-mix(in srgb, var(--crit) 55%, transparent); color:var(--crit); background:color-mix(in srgb, var(--crit) 12%, transparent); font-weight:600; }
.chip.pod { cursor:pointer; }
.linked { display:inline-block; margin-left:8px; font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:.03em; padding:1px 6px; border-radius:999px; color:var(--crit); border:1px solid color-mix(in srgb, var(--crit) 45%, transparent); background:color-mix(in srgb, var(--crit) 12%, transparent); }
.dh-note { font-weight:400; text-transform:none; letter-spacing:0; color:var(--faint); }
.chip.pod:hover { border-color:var(--teal-dim); color:var(--fg); background:color-mix(in srgb, var(--teal) 14%, var(--surface-2)); }
</style>
