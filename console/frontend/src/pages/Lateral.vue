<script setup lang="ts">
import { computed, ref } from 'vue'
import { store, shortImage, clockNs, type ActorTrail } from '../api'

const selectedActorId = ref('')
const selectedNs = ref('')
const movedOnly = ref(true)

const actors = computed<ActorTrail[]>(() => store.lateral?.actors ?? [])
const namespaces = computed<string[]>(() => store.lateral?.namespaces ?? [])

const focused = computed<ActorTrail | null>(() =>
  selectedActorId.value ? actors.value.find(a => a.image_id === selectedActorId.value) ?? null : null)

// Client-side filters. An explicit actor selection wins over the moved/namespace
// filters so a focused actor is always shown, even a single-namespace one.
const filtered = computed<ActorTrail[]>(() => {
  if (selectedActorId.value) return actors.value.filter(a => a.image_id === selectedActorId.value)
  let list = actors.value
  if (movedOnly.value) list = list.filter(a => a.hops >= 1)
  if (selectedNs.value) list = list.filter(a => a.path.includes(selectedNs.value))
  return list
})

const movedCount = computed(() => filtered.value.filter(a => a.hops >= 1).length)

function focusRow(a: ActorTrail) {
  selectedActorId.value = selectedActorId.value === a.image_id ? '' : a.image_id
}

const shortNs = (s: string) => (s.length > 18 ? s.slice(0, 17) + '…' : s)

function chips(list: string[]) {
  const a = list ?? []
  const shown = a.slice(0, 4)
  return { shown, rest: a.length - shown.length }
}

/* Focused path diagram: a horizontal line of namespace circles, earliest left,
   joined by step-numbered arrows. Conventions follow FsmDiagram.vue. */
const R = 20, STEP = 164, PAD = 20, TOP = 26, LBL = 24
const diagram = computed(() => {
  const p = focused.value?.path ?? []
  const cy = PAD + TOP + R
  const nodes = p.map((ns, i) => ({ ns, label: shortNs(ns), i, x: PAD + R + i * STEP, y: cy }))
  const arrows = nodes.slice(0, -1).map((a, i) => {
    const b = nodes[i + 1]
    const sx = a.x + R + 4, ex = b.x - R - 11
    return { sx, ex, y: cy, mx: (sx + ex) / 2, step: i + 1 }
  })
  const w = PAD * 2 + (p.length ? (p.length - 1) * STEP + R * 2 : 0)
  const h = cy + R + LBL + PAD
  return { nodes, arrows, viewBox: `0 0 ${w} ${h}` }
})
</script>

<template>
  <section class="card">
    <div class="hd">
      <h2>Lateral</h2>
      <span class="c">{{ filtered.length }} actors · {{ movedCount }} moved laterally</span>
    </div>

    <p class="intro">
      Lateral movement — a compromised image (an <b>actor</b>) reaching more than one namespace over time.
      Each row is an actor and the namespaces it moved through, earliest first.
    </p>

    <div class="toolbar">
      <label class="fl">Actor
        <select v-model="selectedActorId">
          <option value="">All actors</option>
          <option v-for="a in actors" :key="a.image_id" :value="a.image_id">{{ shortImage(a.image) }}</option>
        </select>
      </label>
      <label class="fl">Namespace
        <select v-model="selectedNs" :disabled="!!selectedActorId">
          <option value="">All namespaces</option>
          <option v-for="n in namespaces" :key="n" :value="n">{{ n }}</option>
        </select>
      </label>
      <button class="chip-f" :class="{ on: movedOnly }" :disabled="!!selectedActorId"
        @click="movedOnly = !movedOnly">Moved only</button>
      <button v-if="selectedActorId" class="chip-f" @click="selectedActorId = ''">Clear focus</button>
    </div>

    <figure v-if="focused" class="pathfig">
      <svg :viewBox="diagram.viewBox" preserveAspectRatio="xMidYMid meet" role="img"
        :aria-label="`Movement path for ${shortImage(focused.image)}: ${focused.path.join(' to ')}`">
        <defs>
          <marker id="lat-arrow" viewBox="0 0 10 10" refX="9" refY="5"
            markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" fill="var(--teal)" />
          </marker>
        </defs>
        <g class="arrows">
          <template v-for="(ar, i) in diagram.arrows" :key="'a' + i">
            <line :x1="ar.sx" :y1="ar.y" :x2="ar.ex" :y2="ar.y" marker-end="url(#lat-arrow)" />
            <text :x="ar.mx" :y="ar.y - 10" text-anchor="middle" class="step">{{ ar.step }}</text>
          </template>
        </g>
        <g class="nodes">
          <g v-for="nd in diagram.nodes" :key="nd.i">
            <circle :cx="nd.x" :cy="nd.y" :r="R" />
            <text :x="nd.x" :y="nd.y" text-anchor="middle" dominant-baseline="central" class="num">{{ nd.i + 1 }}</text>
            <text :x="nd.x" :y="nd.y + R + 15" text-anchor="middle" class="nlbl">{{ nd.label }}<title>{{ nd.ns }}</title></text>
          </g>
        </g>
      </svg>
      <figcaption>
        Path of <b>{{ shortImage(focused.image) }}</b> across {{ focused.namespaces }} namespaces
        ({{ focused.hops }} hops). Each circle is a namespace; arrows run earliest → latest.
      </figcaption>
    </figure>

    <div class="bd" v-if="!actors.length">
      <div class="empty">No incidents in this range.</div>
    </div>
    <div class="bd" v-else-if="!filtered.length">
      <div class="empty">
        <template v-if="movedOnly && !selectedNs">
          No lateral movement detected in this range.
          <button class="btn linkish" @click="movedOnly = false">Show all actors</button>
        </template>
        <template v-else>No actors match these filters.</template>
      </div>
    </div>

    <div class="scroll" v-else>
      <table>
        <thead>
          <tr>
            <th>Actor</th><th>Path</th><th>Hops</th><th>NS</th><th>Pods</th>
            <th>Incidents</th><th>Outcomes</th><th>Rules</th><th>First</th><th>Last</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="a in filtered" :key="a.image_id" class="clickable"
            :class="{ sel: a.image_id === selectedActorId, mover: a.hops >= 1 }" @click="focusRow(a)">
            <td :title="a.image_id">{{ a.image }}</td>
            <td class="path">
              <template v-for="(ns, i) in a.path" :key="i">
                <span v-if="i" class="arr">→</span>
                <span class="chip mono" :class="{ hit: ns === selectedNs }">{{ shortNs(ns) }}</span>
              </template>
            </td>
            <td class="mono">{{ a.hops }}</td>
            <td class="mono">{{ a.namespaces }}</td>
            <td class="mono">{{ a.pods }}</td>
            <td class="mono">{{ a.incidents }}</td>
            <td>
              <span v-if="a.killed" class="act kill">{{ a.killed }} killed</span>
              <span v-if="a.blocked" class="act deny">{{ a.blocked }} blocked</span>
            </td>
            <td class="chips">
              <span v-for="r in chips(a.rules).shown" :key="r" class="chip mono">{{ r }}</span>
              <span v-if="chips(a.rules).rest > 0" class="chip more">+{{ chips(a.rules).rest }}</span>
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
.intro { margin:0; padding:12px 15px; border-bottom:1px solid var(--border); font-size:12.5px; color:var(--fg-2); }
.intro b { color:var(--fg); }

.fl { display:inline-flex; align-items:center; gap:6px; font-size:11.5px; color:var(--muted); }
.fl select { font-family:var(--sans); font-size:12.5px; color:var(--fg); background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:5px 9px; cursor:pointer; max-width:220px; }
.fl select:hover { border-color:var(--teal-dim); }
.fl select:disabled { opacity:.5; cursor:not-allowed; }
.chip-f:disabled { opacity:.5; cursor:not-allowed; }

.pathfig { margin:0; padding:16px 15px; border-bottom:1px solid var(--border); color:var(--fg-2); }
.pathfig svg { display:block; width:100%; max-width:100%; height:auto; }
.pathfig .arrows line { stroke:var(--teal); stroke-width:2; }
.pathfig .step { font-family:var(--mono); font-size:11px; fill:var(--teal); }
.pathfig .nodes circle { fill:currentColor; fill-opacity:.08; stroke:currentColor; stroke-width:1.6; }
.pathfig .num { font-family:var(--mono); font-size:12px; fill:var(--fg); }
.pathfig .nlbl { font-family:var(--mono); font-size:11.5px; fill:var(--fg-2); }
.pathfig figcaption { margin-top:10px; font-size:11.5px; color:var(--faint); max-width:640px; }
.pathfig figcaption b { color:var(--fg-2); }

tbody tr.mover td:first-child { box-shadow:inset 3px 0 0 var(--teal-dim); }
tbody tr.clickable { cursor:pointer; }
tbody tr.sel { background:color-mix(in srgb, var(--teal) 12%, transparent); }
tbody tr.sel:hover { background:color-mix(in srgb, var(--teal) 16%, transparent); }

td.path { white-space:normal; max-width:360px; }
.path .arr { color:var(--faint); margin:0 5px; font-family:var(--mono); }
.act { margin-right:8px; font-size:11.5px; }
.chips { white-space:normal; max-width:240px; }
.chip { display:inline-block; font-size:10.5px; padding:1px 7px; border-radius:999px; margin:1px 2px 1px 0; background:var(--surface-2); border:1px solid var(--border); color:var(--fg-2); }
.chip.hit { border-color:var(--teal-dim); color:var(--fg); background:color-mix(in srgb, var(--teal) 16%, var(--surface-2)); }
.chip.more { color:var(--faint); }
.linkish { margin-left:8px; padding:2px 9px; }
</style>
