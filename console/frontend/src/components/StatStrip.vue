<script setup lang="ts">
// A row of summary stat cards shown above a page's detail table.
defineProps<{ stats: { label: string; value: string | number; hint?: string; tone?: 'crit' | 'warn' | 'teal' }[] }>()
</script>

<template>
  <div class="statstrip">
    <div v-for="(s, i) in stats" :key="i" class="stat" :class="s.tone">
      <div class="v mono">{{ s.value }}</div>
      <div class="l">{{ s.label }}</div>
      <div v-if="s.hint" class="h">{{ s.hint }}</div>
    </div>
  </div>
</template>

<style scoped>
.statstrip { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:16px; }
.stat { background:var(--surface); border:1px solid var(--border); border-radius:var(--r); padding:12px 14px; }
.stat .v { font-size:22px; font-weight:600; line-height:1.1; color:var(--fg); }
.stat .l { font-size:11px; text-transform:uppercase; letter-spacing:.4px; color:var(--faint); margin-top:4px; }
.stat .h { font-size:11.5px; color:var(--muted); margin-top:3px; }
.stat.crit .v { color:var(--crit); }
.stat.warn .v { color:var(--orange); }
.stat.teal .v { color:var(--teal); }
</style>
