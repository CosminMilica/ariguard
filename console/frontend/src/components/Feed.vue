<script setup lang="ts">
import { type AEvent, actLabel, clockNs, openChainModal, sevKey } from '../api'
defineProps<{ events: AEvent[] }>()
const label = (e: AEvent) => actLabel(e.action, e.enforced)
</script>

<template>
  <div class="feed">
    <div v-if="!events.length" class="empty">No events yet.</div>
    <div v-for="(e, i) in events" :key="e.ts_ns + e.pod + i" class="fe clickable" :class="sevKey(e.severity)" @click="openChainModal(e.pod)">
      <div class="sev"></div>
      <div class="time">{{ clockNs(e.ts_ns) }}</div>
      <div class="msg">
        <div class="l1"><b>{{ e.pod }}</b> {{ e.event }}</div>
        <div class="l2">{{ e.rule }} · {{ e.namespace }} · {{ e.node }}</div>
      </div>
      <div class="tail"><span :class="label(e).cls">{{ label(e).text }}</span></div>
    </div>
  </div>
</template>
