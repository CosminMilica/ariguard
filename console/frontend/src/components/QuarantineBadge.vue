<script setup lang="ts">
const props = defineProps<{ mode?: string }>()
const dryrun = (props.mode || '').toLowerCase() === 'dryrun'
const label = dryrun ? 'ISOLATED (dry-run)' : 'ISOLATED'
</script>

<template>
  <span class="qbadge" :class="{ dry: dryrun }" :title="dryrun ? 'Workload would be isolated (dry-run)' : 'Workload autonomously isolated'">
    <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
      <rect x="4" y="11" width="16" height="9" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </svg>
    {{ label }}
  </span>
</template>

<style scoped>
.qbadge {
  display:inline-flex; align-items:center; gap:4px;
  font-size:10.5px; font-weight:700; text-transform:uppercase; letter-spacing:.4px;
  padding:2px 8px; border-radius:999px;
  color:var(--orange);
  background:color-mix(in srgb, var(--orange) 12%, transparent);
  border:1px solid color-mix(in srgb, var(--orange) 45%, transparent);
  white-space:nowrap;
}
.qbadge.dry { color:var(--warn); background:color-mix(in srgb, var(--warn) 10%, transparent); border-color:color-mix(in srgb, var(--warn) 40%, transparent); }
</style>
