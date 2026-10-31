<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref, watch } from 'vue'
import { Chart } from 'chart.js/auto'
import { store } from '../api'

export interface Series { label: string; data: number[]; color: string }
const props = defineProps<{ kind: 'line' | 'bar'; labels?: string[]; series: Series[]; legend?: boolean; times?: number[]; step?: number }>()
const emit = defineEmits<{ (e: 'brush', from: number, to: number): void }>()
const sel = ref<{ l: number; w: number } | null>(null)
const canvas = ref<HTMLCanvasElement>()
let chart: Chart | null = null
let dragX: number | null = null

const pad = (n: number) => String(n).padStart(2, '0')
function fmt(ms: number) { const d = new Date(ms); return `${pad(d.getHours())}:${pad(d.getMinutes())}` }
function stepMs() { const t = props.times; return props.step ?? (t && t.length > 1 ? t[1] - t[0] : 60000) }
function xMin() { return props.times && props.times.length ? props.times[0] : 0 }
function xMax() {
  const t = props.times
  if (!t || !t.length) return 1
  return t[t.length - 1] + (props.kind === 'bar' ? stepMs() : 0)
}
// Exact pixel -> time via the chart's own linear scale.
function timeAt(px: number): number {
  const v = chart!.scales.x.getValueForPixel(px)
  return Math.min(xMax(), Math.max(xMin(), v ?? xMin()))
}
function clampX(e: PointerEvent) {
  const a = chart!.chartArea, r = canvas.value!.getBoundingClientRect()
  return Math.min(a.right, Math.max(a.left, e.clientX - r.left))
}
function down(e: PointerEvent) {
  if (!chart || !props.times || props.times.length < 2 || e.button !== 0) return
  const a = chart.chartArea, r = canvas.value!.getBoundingClientRect()
  const x = e.clientX - r.left, y = e.clientY - r.top
  if (x < a.left || x > a.right || y < a.top || y > a.bottom) return
  dragX = x
  sel.value = { l: x, w: 0 }
  store.brushing = true // freeze the live poll so the axis doesn't shift under the cursor
  canvas.value!.setPointerCapture(e.pointerId)
}
function move(e: PointerEvent) {
  if (dragX == null) return
  const x = clampX(e)
  sel.value = { l: Math.min(x, dragX), w: Math.abs(x - dragX) }
}
function up(e: PointerEvent) {
  if (dragX == null) return
  const x = clampX(e), a = dragX
  dragX = null; sel.value = null; store.brushing = false
  if (Math.abs(x - a) < 6) return
  const f = timeAt(Math.min(a, x)), t = timeAt(Math.max(a, x))
  if (t - f > 1000) emit('brush', Math.round(f), Math.round(t))
}
function cancel() { dragX = null; sel.value = null; store.brushing = false }

const css = (n: string) => getComputedStyle(document.documentElement).getPropertyValue(n).trim()

function points(s: Series) {
  const t = props.times ?? []
  return s.data.map((v, i) => ({ x: t[i] ?? i, y: v }))
}
function datasets() {
  return props.series.map(s => props.kind === 'line'
    ? {
        label: s.label, data: points(s), borderColor: s.color, borderWidth: 1.6, pointRadius: 0, tension: 0.3, fill: true,
        backgroundColor: (ctx: any) => {
          const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, 180)
          g.addColorStop(0, 'rgba(34,193,196,.22)'); g.addColorStop(1, 'rgba(34,193,196,0)')
          return g
        },
      }
    : { label: s.label, data: points(s), backgroundColor: s.color, stack: 's', barThickness: 9 })
}

onMounted(() => {
  Chart.defaults.color = css('--muted')
  Chart.defaults.font.family = 'ui-monospace, monospace'
  Chart.defaults.font.size = 10
  const stacked = props.kind === 'bar'
  chart = new Chart(canvas.value!, {
    type: props.kind,
    data: { datasets: datasets() as any },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: !!props.legend, position: 'bottom', labels: { boxWidth: 9, boxHeight: 9, padding: 10, font: { size: 10.5 } } } },
      scales: {
        x: {
          type: 'linear', stacked, min: xMin(), max: xMax(),
          grid: { display: false },
          ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 8, callback: (v: any) => fmt(Number(v)) },
        },
        y: { stacked, grid: { color: 'rgba(134,149,164,.14)' }, border: { display: false }, ticks: { maxTicksLimit: 4, precision: 0 }, beginAtZero: true },
      },
    },
  })
})

watch(() => [props.times, props.series], () => {
  if (!chart) return
  chart.data.datasets = datasets() as any
  const x: any = chart.options.scales!.x
  x.min = xMin(); x.max = xMax()
  chart.update('none')
}, { deep: true })

onBeforeUnmount(() => chart?.destroy())
</script>

<template>
  <div class="brushwrap">
    <canvas ref="canvas" class="brushable" @pointerdown="down" @pointermove="move" @pointerup="up" @pointercancel="cancel"></canvas>
    <div v-if="sel" class="brushsel" :style="{ left: sel.l + 'px', width: sel.w + 'px' }"></div>
  </div>
</template>
