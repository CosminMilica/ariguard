<script setup lang="ts">
import { store, clockNs, openChainModal, type Incident } from '../api'

const outcomeCls = (o: string) => ({ killed: 'killed', blocked: 'blocked' }[(o || '').toLowerCase()] || 'detected')
const stateLabel = (s: string) => (s || '').replace(/_/g, ' ')
const key = (i: Incident) => i.pod + i.started_ts_ns
</script>

<template>
  <section class="card">
    <div class="hd"><h2>Incidents</h2><span class="c">{{ store.incidents.length }} incidents</span></div>
    <div class="bd">
      <div v-if="!store.incidents.length" class="empty">No incidents in this range.</div>
      <div v-else class="inc-list">
        <article v-for="i in store.incidents" :key="key(i)" class="inc" :class="outcomeCls(i.outcome)">
          <div class="inc-main">
            <div class="inc-pod mono">{{ i.pod }}</div>
            <div class="inc-rule">{{ i.rule }}</div>
            <div class="inc-meta mono">{{ i.namespace }} · {{ i.node }}</div>
          </div>
          <div class="inc-mid">
            <span class="outcome" :class="outcomeCls(i.outcome)">{{ i.outcome || 'detected' }}</span>
            <span class="st-max">max: {{ stateLabel(i.max_state) }}</span>
          </div>
          <div class="inc-time mono">
            {{ clockNs(i.started_ts_ns) }} → {{ clockNs(i.ended_ts_ns) }}
            <span class="dim">{{ i.steps }} steps</span>
          </div>
          <button class="btn" @click="openChainModal(i.pod)">View chain</button>
        </article>
      </div>
    </div>
  </section>
</template>
