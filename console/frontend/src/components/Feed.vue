<script setup lang="ts">
import { type AEvent, actLabel, clockNs, openChainModal, procLabel, sevKey, shortImage } from '../api'
defineProps<{ events: AEvent[] }>()
const label = (e: AEvent) => actLabel(e.action, e.enforced)
const context = (e: AEvent) =>
  [e.rule, e.namespace, e.node, procLabel(e.comm, e.pid), e.hook].filter(Boolean).join(' · ')
</script>

<template>
  <div class="feed">
    <div v-if="!events.length" class="empty">No events yet.</div>
    <div v-for="(e, i) in events" :key="e.ts_ns + e.pod + i" class="fe clickable" :class="sevKey(e.severity)" @click="openChainModal(e.pod)">
      <div class="sev"></div>
      <div class="time">{{ clockNs(e.ts_ns) }}</div>
      <div class="msg">
        <div class="l1"><b>{{ e.pod }}</b> {{ e.event }}<span v-if="e.image" class="img mono" :title="e.image">{{ shortImage(e.image) }}</span></div>
        <div class="l2" :title="context(e)">{{ context(e) }}</div>
      </div>
      <div class="tail"><span :class="label(e).cls">{{ label(e).text }}</span></div>
    </div>
  </div>
</template>

<style scoped>
.img { margin-left:6px; padding:0 5px; border-radius:4px; font-size:11px; color:var(--fg-2); background:var(--hover); }
</style>
