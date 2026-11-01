<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount } from 'vue'
import { store, closeRuleModal, fmtWindow, isKill } from '../api'
import FsmDiagram from './FsmDiagram.vue'

const key = (e: KeyboardEvent) => { if (e.key === 'Escape' && store.selectedRule) closeRuleModal() }
onMounted(() => document.addEventListener('keydown', key))
onBeforeUnmount(() => document.removeEventListener('keydown', key))

const rule = computed(() => store.selectedRule)

// Action -> theme colour. Unknown actions fall back to a neutral token so a new
// action value still renders instead of breaking the diagram.
const ACTION_COLOR: Record<string, string> = {
  observe: 'var(--faint)', throttle: 'var(--warn)', deny: 'var(--orange)', kill: 'var(--crit)',
}
const actColor = (a: string) => ACTION_COLOR[(a || '').toLowerCase()] || 'var(--muted)'

// Join a transition's syscall/predicate descriptions for the table cell. Empty
// when the backend omits them, so the cell degrades to a faint dash.
const syscallText = (s?: string[]) => (Array.isArray(s) && s.length ? s.join(' or ') : '')

// Data for the state-machine diagram, extracted from the rule payload. Null when
// the rule carries no states so the modal can fall back to an empty message.
const fsm = computed(() => {
  const r = rule.value
  if (!r || !Array.isArray(r.states) || !r.states.length) return null
  return {
    states: r.states,
    transitions: Array.isArray(r.transitions) ? r.transitions : [],
    terminalFrom: typeof r.terminal_from === 'number' ? r.terminal_from : r.states.length,
  }
})
</script>

<template>
  <div v-if="rule" class="modal-bg" @click="closeRuleModal">
    <div class="modal wide" @click.stop>
      <div class="mhd">
        <h2 class="mono">{{ rule.name }}</h2>
        <button class="btn" aria-label="Close" @click="closeRuleModal">✕</button>
      </div>
      <div class="mbd">
        <div class="rmeta">
          <div class="kvrow"><span>Scope</span><span class="mono">{{ rule.scope }}</span></div>
          <div class="kvrow"><span>Window</span><span class="mono">{{ fmtWindow(rule.window_ns) }}</span></div>
          <div class="kvrow"><span>Terminal action</span><span class="act" :class="{ kill: isKill(rule.terminal_action) }">{{ isKill(rule.terminal_action) ? 'KILL' : rule.terminal_action }}</span></div>
          <div class="kvrow"><span>Hits</span><span class="mono">{{ rule.hits }}</span></div>
        </div>

        <template v-if="fsm">
          <p class="fsm-note">A state advances when a process in the workload makes the syscall for that event; the action (observe / throttle / deny / kill) is applied at that step.</p>
          <FsmDiagram :states="fsm.states" :transitions="fsm.transitions" :terminal-from="fsm.terminalFrom" />

          <div class="scroll">
            <table>
              <thead><tr><th>From</th><th>Event</th><th>To</th><th>Action</th><th>Syscall</th></tr></thead>
              <tbody>
                <tr v-if="!rule.transitions || !rule.transitions.length"><td colspan="5" class="empty">No transitions.</td></tr>
                <tr v-for="(t, i) in rule.transitions" :key="i">
                  <td class="mono">{{ t.from }}</td>
                  <td class="mono dim">{{ t.event }}</td>
                  <td class="mono">{{ t.to }}</td>
                  <td><span class="act" :style="{ color: actColor(t.action) }">{{ t.action }}</span></td>
                  <td class="syscol mono dim" :title="syscallText(t.syscalls)">{{ syscallText(t.syscalls) || '—' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
        <div v-else class="empty">No state machine data for this rule.</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.rmeta { margin-bottom: 14px; }
.fsm-note { color: var(--muted); font-size: 11.5px; margin: 0 0 10px; }
.syscol { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
