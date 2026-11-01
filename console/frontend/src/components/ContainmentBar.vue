<script setup lang="ts">
import { computed } from 'vue'
import { store, fmtNum } from '../api'

const c = computed(() => store.containment)

const tiles = computed(() => {
  const x = c.value
  return [
    { k: 'Total', v: x ? String(x.total) : '—', d: 'threats', cls: '' },
    { k: 'Killed', v: x ? String(x.killed) : '—', d: 'processes terminated', cls: 'crit' },
    { k: 'Blocked', v: x ? String(x.blocked) : '—', d: 'syscalls denied', cls: 'teal' },
    { k: 'Observed only', v: x ? String(x.observed_only) : '—', d: 'containment gap', cls: x && x.observed_only ? 'crit' : '' },
  ]
})

const actions = computed(() => {
  const a = c.value?.by_action
  if (!a) return []
  const max = Math.max(1, a.kill, a.deny, a.throttle, a.observe)
  return [
    { label: 'kill', n: a.kill, color: 'var(--crit)', max },
    { label: 'deny', n: a.deny, color: 'var(--orange)', max },
    { label: 'throttle', n: a.throttle, color: 'var(--warn)', max },
    { label: 'observe', n: a.observe, color: 'var(--faint)', max },
  ]
})
</script>

<template>
  <section class="stats cont-tiles">
    <div v-for="t in tiles" :key="t.k" class="stat">
      <div class="k">{{ t.k }}</div>
      <div class="v" :class="t.cls">{{ t.v }}</div>
      <div class="d">{{ t.d }}</div>
    </div>
  </section>
  <div class="cols" style="margin-bottom:16px">
    <section class="card">
      <div class="hd"><h2>Action breakdown</h2><span class="c">by enforcement</span></div>
      <div class="bd">
        <div v-if="!actions.length" class="empty">No containment data.</div>
        <div v-else class="brk">
          <div v-for="a in actions" :key="a.label" class="row">
            <span>{{ a.label }}</span>
            <div class="track"><i :style="{ width: (a.n / a.max * 100) + '%', background: a.color }"></i></div>
            <span class="n">{{ fmtNum(a.n) }}</span>
          </div>
        </div>
      </div>
    </section>
    <section class="card">
      <div class="hd"><h2>Gaps</h2><span class="c">observed, not enforced</span></div>
      <div class="bd">
        <div v-if="!c?.gaps?.length" class="empty">No containment gaps.</div>
        <div v-else class="gaps">
          <div v-for="g in c.gaps" :key="g.rule" class="gap-row">
            <span class="mono">{{ g.rule }}</span>
            <span class="gap-n mono">{{ fmtNum(g.observed_only) }} observed</span>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.cont-tiles { grid-template-columns:repeat(4,1fr); }
@media (max-width:540px){ .cont-tiles{ grid-template-columns:repeat(2,1fr);} }
.gaps { display:flex; flex-direction:column; gap:8px; }
.gap-row { display:flex; align-items:center; justify-content:space-between; gap:12px; font-size:12.5px; padding:6px 0; border-bottom:1px solid var(--border-2); }
.gap-row:last-child { border-bottom:0; }
.gap-n { color:var(--crit); font-size:11.5px; }
</style>
