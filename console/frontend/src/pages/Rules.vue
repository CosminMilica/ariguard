<script setup lang="ts">
import { store, fmtWindow, isKill, openRuleModal } from '../api'
import type { Rule } from '../api'

const ORDER = ['observe', 'throttle', 'deny', 'kill']
// The product enforces autonomously in-kernel; a rule mixes actions along its chain
// (e.g. observe -> deny -> kill), so show the whole mix, not just the terminal state.
function actionMix(r: Rule): string[] {
  const seen = new Set((r.transitions ?? []).map((t) => t.action))
  seen.add(r.terminal_action)
  return ORDER.filter((a) => seen.has(a))
}
</script>

<template>
  <section class="card">
    <div class="hd"><h2>Rules</h2><span class="c">compiled bundle · {{ store.rules.length }} rules</span></div>
    <div class="scroll">
      <table>
        <thead><tr><th>Rule</th><th>Scope</th><th>States</th><th>Window</th><th>Enforcement</th><th>Hits</th><th></th></tr></thead>
        <tbody>
          <tr v-if="!store.rules.length"><td colspan="7" class="empty">No rules registered yet.</td></tr>
          <tr v-for="r in store.rules" :key="r.name" class="clickable" title="View state machine" @click="openRuleModal(r)">
            <td class="mono">{{ r.name }}</td><td class="mono dim">{{ r.scope }}</td><td class="mono">{{ r.num_states }}</td>
            <td class="mono">{{ fmtWindow(r.window_ns) }}</td>
            <td><span v-for="a in actionMix(r)" :key="a" class="act" :class="{ kill: isKill(a) }">{{ a.toUpperCase() }}</span></td>
            <td class="mono">{{ r.hits }}</td>
            <td class="rv dim" aria-hidden="true">›</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<style scoped>
tr.clickable { cursor: pointer; }
.act + .act { margin-left: 4px; }
.rv { text-align: right; color: var(--faint); opacity: .45; transition: opacity .12s, color .12s; }
tr.clickable:hover .rv { opacity: 1; color: var(--teal); }
</style>
