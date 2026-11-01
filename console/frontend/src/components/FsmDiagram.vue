<script setup lang="ts">
import { computed, reactive, ref } from 'vue'

interface Transition { from: string; event: string; to: string; action: string; syscalls?: string[] }

const props = defineProps<{
  states: string[]
  transitions: Transition[]
  terminalFrom: number
}>()

// Action -> theme colour. Unknown actions fall back to a neutral token so a new
// action value still renders instead of breaking the diagram.
const ACTION_COLOR: Record<string, string> = {
  observe: 'var(--faint)', throttle: 'var(--warn)', deny: 'var(--orange)', kill: 'var(--crit)',
}
const actColor = (a: string) => ACTION_COLOR[(a || '').toLowerCase()] || 'var(--muted)'
const mid = (a: string) => 'fsm-ar-' + ((a || 'x').toLowerCase().replace(/[^a-z0-9]/g, '') || 'x')

// Join a transition's syscall/predicate descriptions. Empty when absent so the
// tooltip and edge title degrade gracefully (the detail is simply omitted).
const syscallText = (s?: string[]) => (Array.isArray(s) && s.length ? s.join(' or ') : '')

const NODE_H = 36
const CHAR_W = 7.2          // node-label char width (11.5px mono)
const LCHAR = 6.1           // edge-label char width (10.5px mono)
const GAP = 96              // generous horizontal gap between node boxes
const PAD = 16              // outer viewBox padding
const LBL_H = 16            // forward-label band row height
const LBL_GAP = 4           // vertical gap between forward-label rows
const TOP_GAP = 10          // gap between node top and first forward-label row
const MAX_EDGE_CHARS = 26   // truncate long edge labels (full text in <title>)

const edgeW = (s: string) => s.length * LCHAR + 12

const layout = computed(() => {
  const states = props.states
  const terminalFrom = typeof props.terminalFrom === 'number' ? props.terminalFrom : states.length
  const idx = new Map<string, number>()
  states.forEach((s, i) => idx.set(s, i))

  const maxLen = Math.max(1, ...states.map(s => (s || '').length))
  const nodeW = Math.min(168, Math.max(76, maxLen * CHAR_W + 24))
  const nodeChars = Math.max(3, Math.floor((nodeW - 16) / CHAR_W))
  const stepX = nodeW + GAP
  const cx = (i: number) => i * stepX + nodeW / 2

  // Index-mapped edges, skipping any transition that references a missing state.
  const edges = props.transitions
    .map(t => ({ from: idx.get(t.from), to: idx.get(t.to), event: t.event, action: t.action, toName: t.to, syscalls: t.syscalls }))
    .filter((e): e is { from: number; to: number; event: string; action: string; toName: string; syscalls: string[] | undefined } =>
      e.from !== undefined && e.to !== undefined)

  // --- forward (i -> i+1) label rows: stagger into bands so they never overlap ---
  const rowIntervals: { l: number; r: number }[][] = []
  const assignRow = (l: number, r: number) => {
    for (let ri = 0; ri < rowIntervals.length; ri++) {
      if (rowIntervals[ri].every(iv => r < iv.l - 6 || l > iv.r + 6)) { rowIntervals[ri].push({ l, r }); return ri }
    }
    rowIntervals.push([{ l, r }]); return rowIntervals.length - 1
  }

  const hasSelf = edges.some(e => e.to === e.from)
  const forwardEdges = edges.filter(e => e.to === e.from + 1)
  const fwdRows = forwardEdges.map(e => {
    const midX = (cx(e.from) + cx(e.to)) / 2
    const w = edgeW(trunc(label(e)).text)
    return assignRow(midX - w / 2, midX + w / 2)
  })
  const numRows = rowIntervals.length
  const forwardRegionH = numRows > 0 ? TOP_GAP + numRows * LBL_H + (numRows - 1) * LBL_GAP : 0
  const selfRise = forwardRegionH + 30          // self-loop apex clears the forward rows
  const selfRegionH = hasSelf ? selfRise + 14 : 0
  const aboveExtra = Math.max(forwardRegionH, selfRegionH)

  const nodeTop = PAD + aboveExtra
  const centerY = nodeTop + NODE_H / 2
  const nodeBottom = nodeTop + NODE_H

  // Bounds tracking so the viewBox fits every node + label band + arc.
  let minX = 0, maxX = (states.length - 1) * stepX + nodeW, minY = nodeTop, maxY = nodeBottom
  const grow = (x: number, y: number) => { if (x < minX) minX = x; if (x > maxX) maxX = x; if (y < minY) minY = y; if (y > maxY) maxY = y }

  function label(e: { event: string; action: string }) { return `${e.event} · ${e.action}` }
  function trunc(s: string) {
    return s.length > MAX_EDGE_CHARS ? { text: s.slice(0, MAX_EDGE_CHARS - 1) + '…', full: s } : { text: s, full: s }
  }

  type Path = { d: string; color: string; mk: string; lx: number; ly: number; lw: number; lh: number; text: string; full: string; sys: string }
  const paths: Path[] = []
  const pushLabel = (lx: number, ly: number, text: string) => {
    const lw = edgeW(text), lh = 15
    grow(lx - lw / 2, ly - lh / 2); grow(lx + lw / 2, ly + lh / 2)
    return { lw, lh }
  }

  // forward adjacent: straight line on the centre line, label floats in its band
  forwardEdges.forEach((e, i) => {
    const sx = cx(e.from) + nodeW / 2, ex = cx(e.to) - nodeW / 2
    const row = fwdRows[i]
    const ly = nodeTop - TOP_GAP - LBL_H / 2 - row * (LBL_H + LBL_GAP)
    const { text, full } = trunc(label(e))
    const { lw, lh } = pushLabel((sx + ex) / 2, ly, text)
    paths.push({ d: `M ${sx} ${centerY} L ${ex} ${centerY}`, color: actColor(e.action), mk: mid(e.action), lx: (sx + ex) / 2, ly, lw, lh, text, full, sys: syscallText(e.syscalls) })
  })

  // self loops: arc above the node, label above the apex
  edges.filter(e => e.to === e.from).forEach(e => {
    const x = cx(e.from), a = selfRise
    const apexY = nodeTop - a
    const d = `M ${x - 13} ${nodeTop} C ${x - 13} ${apexY} ${x + 13} ${apexY} ${x + 13} ${nodeTop}`
    const ly = apexY - 7
    const { text, full } = trunc(label(e))
    const { lw, lh } = pushLabel(x, ly, text)
    paths.push({ d, color: actColor(e.action), mk: mid(e.action), lx: x, ly, lw, lh, text, full, sys: syscallText(e.syscalls) })
  })

  // back-edges + forward-skips: arc below, label on the arc near the apex
  const dup = new Map<string, number>()
  edges.filter(e => e.to < e.from || e.to > e.from + 1).forEach(e => {
    const span = Math.abs(e.to - e.from)
    const pkey = `${Math.min(e.from, e.to)}-${Math.max(e.from, e.to)}`
    const occ = dup.get(pkey) || 0; dup.set(pkey, occ + 1)
    const depth = 26 + span * 15 + occ * 16
    const x1 = cx(e.from), x2 = cx(e.to), mx = (x1 + x2) / 2
    const d = `M ${x1} ${nodeBottom} Q ${mx} ${nodeBottom + depth * 2} ${x2} ${nodeBottom}`
    const ly = nodeBottom + depth + 4
    const { text, full } = trunc(label(e))
    const { lw, lh } = pushLabel(mx, ly, text)
    paths.push({ d, color: actColor(e.action), mk: mid(e.action), lx: mx, ly, lw, lh, text, full, sys: syscallText(e.syscalls) })
  })

  const nodes = states.map((s, i) => {
    const full = s || ''
    const out = edges.filter(e => e.from === i).map(e => ({ event: e.event, to: e.toName, action: e.action, color: actColor(e.action), sys: syscallText(e.syscalls) }))
    const inCount = edges.filter(e => e.to === i).length
    return {
      i, x: i * stepX, y: nodeTop, w: nodeW, h: NODE_H, cx: cx(i), cy: centerY,
      label: full.length > nodeChars ? full.slice(0, nodeChars - 1) + '…' : full,
      full, terminal: i >= terminalFrom, out, inCount,
    }
  })

  const markers = Array.from(new Set(edges.map(e => e.action))).map(a => ({ id: mid(a), color: actColor(a) }))

  const x0 = minX - PAD, y0 = minY - PAD
  const viewW = (maxX - minX) + PAD * 2, viewH = (maxY - minY) + PAD * 2
  return { nodes, paths, markers, viewBox: `${x0} ${y0} ${viewW} ${viewH}`, viewW, viewH }
})

// ---------------------------------------------------------------- zoom + pan --
const svgEl = ref<SVGSVGElement | null>(null)
const view = reactive({ k: 1, tx: 0, ty: 0 })
const dragging = ref(false)
const K_MIN = 0.4, K_MAX = 4

function toUser(e: { clientX: number; clientY: number }) {
  const svg = svgEl.value
  if (!svg) return { x: 0, y: 0 }
  const pt = svg.createSVGPoint(); pt.x = e.clientX; pt.y = e.clientY
  const m = svg.getScreenCTM(); if (!m) return { x: 0, y: 0 }
  const p = pt.matrixTransform(m.inverse())
  return { x: p.x, y: p.y }
}

function zoomAt(ux: number, uy: number, factor: number) {
  const k2 = Math.min(K_MAX, Math.max(K_MIN, view.k * factor))
  if (k2 === view.k) return
  // keep the user-space point (ux,uy) under the cursor fixed
  view.tx = ux - (ux - view.tx) * (k2 / view.k)
  view.ty = uy - (uy - view.ty) * (k2 / view.k)
  view.k = k2
}

function onWheel(e: WheelEvent) {
  e.preventDefault()
  const u = toUser(e)
  zoomAt(u.x, u.y, e.deltaY < 0 ? 1.12 : 1 / 1.12)
}

let ctmA = 1, ctmD = 1, last = { x: 0, y: 0 }
function onPointerDown(e: PointerEvent) {
  const svg = svgEl.value; if (!svg) return
  const m = svg.getScreenCTM(); if (!m) return
  ctmA = m.a || 1; ctmD = m.d || 1
  last = { x: e.clientX, y: e.clientY }
  dragging.value = true
  hover.show = false
  svg.setPointerCapture(e.pointerId)
}
function onPointerMove(e: PointerEvent) {
  if (!dragging.value) return
  view.tx += (e.clientX - last.x) / ctmA
  view.ty += (e.clientY - last.y) / ctmD
  last = { x: e.clientX, y: e.clientY }
}
function onPointerUp(e: PointerEvent) {
  dragging.value = false
  svgEl.value?.releasePointerCapture?.(e.pointerId)
}

function zoomBtn(factor: number) {
  zoomAt(layout.value.viewW / 2, layout.value.viewH / 2, factor)
}
function fit() { view.k = 1; view.tx = 0; view.ty = 0 }

// ---------------------------------------------------------------- tooltip ----
const wrapEl = ref<HTMLElement | null>(null)
const hover = reactive({ show: false, x: 0, y: 0, i: -1 })
const hoverNode = computed(() => layout.value.nodes[hover.i] || null)

function onNodeEnter(i: number, e: MouseEvent) { hover.i = i; hover.show = !dragging.value; moveTip(e) }
function onNodeMove(e: MouseEvent) { if (hover.show) moveTip(e) }
function onNodeLeave() { hover.show = false }
function moveTip(e: MouseEvent) {
  const r = wrapEl.value?.getBoundingClientRect(); if (!r) return
  let x = e.clientX - r.left + 14, y = e.clientY - r.top + 14
  x = Math.min(x, r.width - 230); y = Math.min(y, r.height - 20)
  hover.x = Math.max(6, x); hover.y = Math.max(6, y)
}
</script>

<template>
  <figure class="fsm" role="img"
    :aria-label="`State machine: ${layout.nodes.length} states, ${transitions.length} transitions`">
    <div class="fsm-wrap" ref="wrapEl">
      <div class="fsm-ctl">
        <button class="btn" type="button" aria-label="Zoom in" title="Zoom in" @click="zoomBtn(1.25)">+</button>
        <button class="btn" type="button" aria-label="Zoom out" title="Zoom out" @click="zoomBtn(1 / 1.25)">−</button>
        <button class="btn" type="button" aria-label="Fit" title="Fit to view" @click="fit">Reset</button>
      </div>
      <svg ref="svgEl" :viewBox="layout.viewBox" preserveAspectRatio="xMidYMid meet"
        class="fsm-svg" :class="{ grabbing: dragging }"
        @wheel="onWheel" @pointerdown="onPointerDown" @pointermove="onPointerMove"
        @pointerup="onPointerUp" @pointercancel="onPointerUp">
        <defs>
          <marker v-for="m in layout.markers" :key="m.id" :id="m.id" viewBox="0 0 10 10"
            refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" :fill="m.color" />
          </marker>
        </defs>
        <g :transform="`translate(${view.tx},${view.ty}) scale(${view.k})`">
          <g class="fsm-edges">
            <template v-for="(p, i) in layout.paths" :key="i">
              <path :d="p.d" fill="none" :stroke="p.color" stroke-width="1.6" :marker-end="`url(#${p.mk})`" />
              <rect :x="p.lx - p.lw / 2" :y="p.ly - p.lh / 2" :width="p.lw" :height="p.lh" rx="3" class="fsm-lbg" />
              <text :x="p.lx" :y="p.ly" text-anchor="middle" dominant-baseline="central"
                class="fsm-elabel" :fill="p.color">{{ p.text }}<title>{{ p.full }}{{ p.sys ? '  [' + p.sys + ']' : '' }}</title></text>
            </template>
          </g>
          <g class="fsm-nodes">
            <g v-for="n in layout.nodes" :key="n.i" class="fsm-node" :class="{ terminal: n.terminal }"
              @mouseenter="onNodeEnter(n.i, $event)" @mousemove="onNodeMove" @mouseleave="onNodeLeave">
              <title>{{ n.full }}</title>
              <rect :x="n.x" :y="n.y" :width="n.w" :height="n.h" rx="6" />
              <text :x="n.cx" :y="n.cy" text-anchor="middle" dominant-baseline="central">{{ n.label }}</text>
            </g>
          </g>
        </g>
      </svg>

      <div v-if="hover.show && hoverNode" class="fsm-tip" :style="{ left: hover.x + 'px', top: hover.y + 'px' }">
        <div class="tip-hd">
          <span class="mono">{{ hoverNode.full }}</span>
          <span class="tip-tag" :class="{ term: hoverNode.terminal }">{{ hoverNode.terminal ? 'terminal' : 'state' }} · #{{ hoverNode.i }}</span>
        </div>
        <div class="tip-sub">incoming: {{ hoverNode.inCount }} · outgoing: {{ hoverNode.out.length }}</div>
        <ul v-if="hoverNode.out.length" class="tip-out">
          <li v-for="(o, oi) in hoverNode.out" :key="oi">
            <span class="mono tip-ev">{{ o.event }}</span>
            <span class="tip-arr">→</span>
            <span class="mono">{{ o.to }}</span>
            <span class="tip-act" :style="{ color: o.color }">{{ o.action }}</span>
            <span v-if="o.sys" class="mono tip-sys">[{{ o.sys }}]</span>
          </li>
        </ul>
        <div v-else class="tip-none">no outgoing transitions</div>
      </div>
    </div>
  </figure>
</template>

<style scoped>
.fsm { margin: 0 0 14px; padding: 0; }
.fsm-wrap { position: relative; background: var(--bg-2); border: 1px solid var(--border); border-radius: var(--r); overflow: hidden; }
.fsm-svg { display: block; width: 100%; height: 340px; cursor: grab; touch-action: none; }
.fsm-svg.grabbing { cursor: grabbing; }
.fsm-ctl { position: absolute; top: 8px; right: 8px; z-index: 2; display: flex; gap: 4px; }
.fsm-ctl .btn { padding: 2px 8px; min-width: 26px; font-size: 13px; line-height: 1.3; font-family: var(--mono); }

.fsm-node rect { fill: var(--surface-2); stroke: var(--border); stroke-width: 1.4; cursor: pointer; }
.fsm-node:hover rect { stroke: var(--teal); }
.fsm-node.terminal rect { stroke: var(--crit); stroke-width: 1.9; }
.fsm-node text { fill: var(--fg); font-family: var(--mono); font-size: 11.5px; pointer-events: none; }
.fsm-node.terminal text { fill: var(--crit); }

.fsm-lbg { fill: var(--bg-2); opacity: .9; }
.fsm-elabel { font-family: var(--mono); font-size: 10.5px; }

.fsm-tip { position: absolute; z-index: 3; pointer-events: none; min-width: 170px; max-width: 230px;
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; box-shadow: var(--shadow); padding: 8px 10px; }
.fsm-tip .tip-hd { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
.fsm-tip .tip-hd .mono { font-size: 12px; font-weight: 600; overflow-wrap: anywhere; }
.fsm-tip .tip-tag { font-size: 9.5px; text-transform: uppercase; letter-spacing: .4px; color: var(--faint); white-space: nowrap; }
.fsm-tip .tip-tag.term { color: var(--crit); }
.fsm-tip .tip-sub { font-size: 10.5px; color: var(--muted); margin-top: 3px; }
.fsm-tip .tip-out { list-style: none; margin: 6px 0 0; padding: 0; display: flex; flex-direction: column; gap: 3px; }
.fsm-tip .tip-out li { font-size: 11px; display: flex; align-items: baseline; gap: 5px; flex-wrap: wrap; }
.fsm-tip .tip-ev { color: var(--teal); }
.fsm-tip .tip-arr { color: var(--faint); }
.fsm-tip .tip-act { margin-left: auto; font-size: 10.5px; }
.fsm-tip .tip-sys { flex-basis: 100%; color: var(--faint); font-size: 10px; overflow-wrap: anywhere; }
.fsm-tip .tip-none { font-size: 10.5px; color: var(--faint); margin-top: 5px; }
</style>
