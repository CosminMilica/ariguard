<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount } from 'vue'
import { store, closeChainModal, actLabel, clockNs, isKill, procLabel, type ChainStep } from '../api'
import ProcTree from './ProcTree.vue'

const key = (e: KeyboardEvent) => { if (e.key === 'Escape' && store.chainModalPod) closeChainModal() }
onMounted(() => document.addEventListener('keydown', key))
onBeforeUnmount(() => document.removeEventListener('keydown', key))

const stateLabel = (s: string) => (s || '').replace(/_/g, ' ')
const outcomeCls = (o: string) => ({ killed: 'killed', blocked: 'blocked' }[(o || '').toLowerCase()] || 'detected')

// Incident summary for this pod — newest matching incident, if the backend has one.
const incident = computed(() => {
  const pod = store.chainModalPod
  return store.incidents
    .filter(i => i.pod === pod)
    .sort((a, b) => b.started_ts_ns - a.started_ts_ns)[0] || null
})

// Enrich each chain step with the from→to transition (derived from the prior
// step's state) and the colored action label.
const steps = computed(() => {
  const list = store.modalChain
  return list.map((s: ChainStep, i: number) => ({
    ...s,
    from: i > 0 ? list[i - 1].state : 'normal',
    to: s.state,
    proc: procLabel(s.comm, s.pid),
    act: actLabel(s.action, s.enforced),
    cls: isKill(s.action) && s.enforced ? 'kill' : s.state !== 'normal' ? 'hit' : '',
  }))
})
</script>

<template>
  <div v-if="store.chainModalPod" class="modal-bg" @click="closeChainModal">
    <div class="modal wide" @click.stop>
      <div class="mhd">
        <h2 class="mono">{{ store.chainModalPod }}</h2>
        <button class="btn" aria-label="Close" @click="closeChainModal">✕</button>
      </div>
      <div class="mbd">
        <div class="an-sum">
          <div class="an-kv"><span>Rule</span><b class="mono">{{ incident?.rule || '—' }}</b></div>
          <div class="an-kv"><span>Node</span><b class="mono">{{ incident?.node || '—' }}</b></div>
          <div class="an-kv" v-if="incident?.namespace"><span>Namespace</span><b class="mono">{{ incident.namespace }}</b></div>
          <div class="an-kv">
            <span>Outcome</span>
            <b v-if="incident"><span class="outcome" :class="outcomeCls(incident.outcome)">{{ incident.outcome || 'detected' }}</span></b>
            <b v-else class="dim">—</b>
          </div>
          <div class="an-kv" v-if="incident"><span>Max state</span><b class="mono">{{ stateLabel(incident.max_state) }}</b></div>
          <div class="an-kv"><span>Steps</span><b class="mono">{{ steps.length }}</b></div>
        </div>

        <div v-if="steps.length" class="pt-wrap">
          <div class="pt-hd">Process tree</div>
          <ProcTree :steps="store.modalChain" />
        </div>

        <div v-if="!steps.length" class="empty">No chain recorded for this pod.</div>
        <div v-else class="scroll an-tl">
          <table>
            <thead>
              <tr><th>Time</th><th>Syscall</th><th>Process</th><th>Event</th><th>Transition</th><th>Action</th></tr>
            </thead>
            <tbody>
              <tr v-for="(s, i) in steps" :key="i" :class="s.cls">
                <td class="mono dim">{{ clockNs(s.ts_ns) }}</td>
                <td class="mono an-hook">{{ s.hook || '—' }}</td>
                <td class="mono">{{ s.proc || '—' }}</td>
                <td>{{ s.event }}</td>
                <td class="mono an-tr"><span class="dim">{{ stateLabel(s.from) }}</span> → <span>{{ stateLabel(s.to) }}</span></td>
                <td><span :class="s.act.cls">{{ s.act.text }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.pt-hd { font-size: 10px; text-transform: uppercase; letter-spacing: .4px; color: var(--faint); margin-bottom: 6px; }
</style>
