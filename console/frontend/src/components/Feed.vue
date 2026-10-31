<script setup lang="ts">
import { type AEvent, clockNs, isKill, openChainModal, sevKey } from '../api'
defineProps<{ events: AEvent[] }>()
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
      <div class="tail"><span v-if="isKill(e.action) && e.enforced" class="act kill">KILL</span><span v-else class="dim">{{ isKill(e.action) ? 'would kill' : 'observe' }}</span></div>
    </div>
  </div>
</template>
