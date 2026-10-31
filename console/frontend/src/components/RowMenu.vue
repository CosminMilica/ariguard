<script setup lang="ts">
defineProps<{ x: number; y: number; muted: boolean }>()
defineEmits<{ (e: 'action', a: 'details' | 'chain' | 'copy' | 'mute'): void }>()
const ic = (d: string) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">${d}</svg>`
</script>

<template>
  <Teleport to="body">
    <div class="menu" :style="{ left: x + 'px', top: y + 'px' }" @click.stop>
      <button @click="$emit('action', 'details')"><span v-html="ic('<circle cx=&quot;11&quot; cy=&quot;11&quot; r=&quot;7&quot;/><path d=&quot;m20 20-3-3&quot;/>')"></span> View details</button>
      <button @click="$emit('action', 'chain')"><span v-html="ic('<path d=&quot;M4 18V9m5 9V5m5 13v-6m5 6V8&quot;/>')"></span> Inspect attack chain</button>
      <button @click="$emit('action', 'copy')"><span v-html="ic('<rect x=&quot;9&quot; y=&quot;9&quot; width=&quot;11&quot; height=&quot;11&quot; rx=&quot;2&quot;/><path d=&quot;M5 15V5a2 2 0 0 1 2-2h10&quot;/>')"></span> Copy name</button>
      <div class="div"></div>
      <button class="danger" @click="$emit('action', 'mute')"><span v-html="ic('<path d=&quot;M4 4l16 16M9 5a3 3 0 0 1 6 0v4&quot;/>')"></span> {{ muted ? 'Unmute alerts' : 'Mute alerts' }}</button>
    </div>
  </Teleport>
</template>
