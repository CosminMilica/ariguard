<script setup lang="ts">
import { computed } from 'vue'
import { store, shortImage, type LatNode, type LatEdge } from '../api'

const data = computed(() => store.lateral ?? { nodes: [] as LatNode[], edges: [] as LatEdge[] })
const nodeCount = computed(() => data.value.nodes.length)
const hopCount = computed(() => data.value.edges.length)

// viewBox is fixed; the <svg> scales to its container, so it stays correct at
// any width. Nodes sit on a circle; edges are quadratic curves bent to one side
// so A->B and B->A never overlap.
const VW = 720, VH = 520
const CX = VW / 2, CY = VH / 2
const LAYOUT_R = 170

const shortLabel = (s: string) => (s.length > 18 ? s.slice(0, 17) + '…' : s)

const graph = computed(() => {
  const ns = data.value.nodes
  const edges = data.value.edges
  const n = ns.length

  const maxInc = Math.max(1, ...ns.map(x => x.incidents))
  const maxCount = Math.max(1, ...edges.map(e => e.count))

  // node placement: evenly spaced around a circle, first node at the top
  const pos = new Map<string, { x: number; y: number; r: number }>()
  const nodes = ns.map((d, i) => {
    const ang = n <= 1 ? -Math.PI / 2 : -Math.PI / 2 + (i * 2 * Math.PI) / n
    const x = n <= 1 ? CX : CX + Math.cos(ang) * LAYOUT_R
    const y = n <= 1 ? CY : CY + Math.sin(ang) * LAYOUT_R
    const r = 14 + (d.incidents / maxInc) * 16
    pos.set(d.namespace, { x, y, r })
    const ca = Math.cos(ang), sa = Math.sin(ang)
    const anchor = ca > 0.3 ? 'start' : ca < -0.3 ? 'end' : 'middle'
    return {
      ns: d.namespace, label: shortLabel(d.namespace), incidents: d.incidents, pods: d.pods,
      x, y, r,
      lx: x + ca * (r + 7), ly: y + sa * (r + 7) + (sa > 0.3 ? 11 : 0), anchor,
    }
  })

  const hops = edges.map(e => {
    const a = pos.get(e.from), b = pos.get(e.to)
    if (!a || !b || e.from === e.to) return null
    const dx = b.x - a.x, dy = b.y - a.y
    const dist = Math.hypot(dx, dy) || 1
    // control point: midpoint pushed along the left-perpendicular of travel, so
    // the opposite direction (which flips dx,dy) bends to the other physical side
    const px = -dy / dist, py = dx / dist
    const bend = 26
    const cx = (a.x + b.x) / 2 + px * bend
    const cy = (a.y + b.y) / 2 + py * bend
    // trim endpoints to the circle boundaries along the curve's tangent
    const sdx = cx - a.x, sdy = cy - a.y, sl = Math.hypot(sdx, sdy) || 1
    const edx = cx - b.x, edy = cy - b.y, el = Math.hypot(edx, edy) || 1
    const sx = a.x + (sdx / sl) * a.r
    const sy = a.y + (sdy / sl) * a.r
    const ex = b.x + (edx / el) * (b.r + 7)
    const ey = b.y + (edy / el) * (b.r + 7)
    // label at the curve's midpoint (quadratic at t=0.5)
    const mx = 0.25 * sx + 0.5 * cx + 0.25 * ex
    const my = 0.25 * sy + 0.5 * cy + 0.25 * ey
    const top = e.count === maxCount
    const imgs = Array.isArray(e.images) ? e.images : []
    return {
      from: e.from, to: e.to, count: e.count, images: imgs, top,
      d: `M ${sx.toFixed(1)} ${sy.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${ex.toFixed(1)} ${ey.toFixed(1)}`,
      w: 1.4 + (e.count / maxCount) * 3.6,
      label: imgs.length > 1 ? `${e.count} · ${imgs.length} img` : `${e.count}`,
      lw: (imgs.length > 1 ? `${e.count} · ${imgs.length} img` : `${e.count}`).length * 6.2 + 8,
      lx: mx, ly: my,
    }
  }).filter((h): h is NonNullable<typeof h> => h !== null)

  return { nodes, hops }
})

function imagesShort(images: string[]): string {
  const a = images ?? []
  if (!a.length) return '—'
  const first = shortImage(a[0]) || a[0]
  return a.length > 1 ? `${first} +${a.length - 1}` : first
}
</script>

<template>
  <section class="card">
    <div class="hd">
      <h2>Lateral</h2>
      <span class="c">{{ nodeCount }} namespaces · {{ hopCount }} movement hops</span>
    </div>

    <div class="bd" v-if="!nodeCount">
      <div class="empty">No namespace activity in this range.</div>
    </div>

    <template v-else>
      <figure class="lat">
        <svg :viewBox="`0 0 ${VW} ${VH}`" preserveAspectRatio="xMidYMid meet" role="img"
          :aria-label="`Lateral movement graph: ${nodeCount} namespaces, ${hopCount} movement hops`">
          <defs>
            <marker id="lat-arrow" viewBox="0 0 10 10" refX="9" refY="5"
              markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0 0 L10 5 L0 10 z" fill="currentColor" />
            </marker>
            <marker id="lat-arrow-top" viewBox="0 0 10 10" refX="9" refY="5"
              markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0 0 L10 5 L0 10 z" fill="var(--orange)" />
            </marker>
          </defs>

          <g class="lat-edges">
            <template v-for="(h, i) in graph.hops" :key="'e' + i">
              <path :d="h.d" fill="none" :class="{ top: h.top }" :stroke-width="h.w"
                :marker-end="h.top ? 'url(#lat-arrow-top)' : 'url(#lat-arrow)'">
                <title>{{ h.from }} → {{ h.to }} · {{ h.count }} hop(s){{ h.images.length ? ', ' + h.images.length + ' image(s)' : '' }}</title>
              </path>
              <rect :x="h.lx - h.lw / 2" :y="h.ly - 8" :width="h.lw" height="16" rx="3" class="lat-lbg" />
              <text :x="h.lx" :y="h.ly" text-anchor="middle" dominant-baseline="central"
                class="lat-elabel" :class="{ top: h.top }">{{ h.label }}</text>
            </template>
          </g>

          <g class="lat-nodes">
            <g v-for="nd in graph.nodes" :key="nd.ns">
              <circle :cx="nd.x" :cy="nd.y" :r="nd.r" />
              <text :x="nd.lx" :y="nd.ly" :text-anchor="nd.anchor" dominant-baseline="central" class="lat-nlabel">
                {{ nd.label }}<title>{{ nd.ns }} · {{ nd.incidents }} incidents · {{ nd.pods }} pods</title>
              </text>
            </g>
          </g>
        </svg>
        <figcaption>
          Each circle is a namespace that had incidents (radius by incident count). An arrow A→B means the
          same actor image appeared in A then later in B; thicker, accented arrows carry more hops.
        </figcaption>
      </figure>

      <div class="bd" v-if="!hopCount">
        <div class="empty">No lateral movement observed in this range.</div>
      </div>

      <div class="scroll" v-else>
        <table>
          <thead>
            <tr><th>From</th><th></th><th>To</th><th>Hops</th><th>Images</th></tr>
          </thead>
          <tbody>
            <tr v-for="(h, i) in graph.hops" :key="'r' + i">
              <td class="mono">{{ h.from }}</td>
              <td class="dim">→</td>
              <td class="mono">{{ h.to }}</td>
              <td class="mono">{{ h.count }}</td>
              <td class="mono dim" :title="h.images.join('\n')">{{ imagesShort(h.images) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </section>
</template>

<style scoped>
.lat { margin: 0; padding: 14px 15px; border-bottom: 1px solid var(--border); color: var(--fg-2); }
.lat svg { display: block; width: 100%; max-width: 100%; height: auto; }

.lat-edges path { stroke: currentColor; opacity: .55; }
.lat-edges path.top { stroke: var(--orange); opacity: .95; }
.lat-lbg { fill: var(--surface); opacity: .9; }
.lat-elabel { font-family: var(--mono); font-size: 11px; fill: var(--fg-2); }
.lat-elabel.top { fill: var(--orange); }

.lat-nodes circle { fill: currentColor; fill-opacity: .08; stroke: currentColor; stroke-width: 1.6; }
.lat-nlabel { font-family: var(--mono); font-size: 11.5px; fill: var(--fg); }

.lat figcaption { margin-top: 10px; font-size: 11.5px; color: var(--faint); max-width: 640px; }
</style>
