<script setup lang="ts">
import { computed } from 'vue'
import { store, type Page } from '../api'

const items: { page: Page; label: string; icon: string }[] = [
  { page: 'overview', label: 'Overview', icon: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>' },
  { page: 'triage', label: 'Triage', icon: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>' },
  { page: 'workloads', label: 'Workloads', icon: '<rect x="3" y="4" width="18" height="5" rx="1"/><rect x="3" y="11" width="18" height="5" rx="1"/><rect x="3" y="18" width="18" height="3" rx="1"/>' },
  { page: 'events', label: 'Events', icon: '<path d="M4 18V9m5 9V5m5 13v-6m5 6V8"/>' },
  { page: 'incidents', label: 'Incidents', icon: '<path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 10v4m0 3v.01"/>' },
  { page: 'campaigns', label: 'Campaigns', icon: '<circle cx="12" cy="12" r="2"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="10"/>' },
  { page: 'actors', label: 'Actors', icon: '<circle cx="12" cy="8" r="3.5"/><circle cx="12" cy="12" r="9"/><path d="M6 19a6 6 0 0 1 12 0"/>' },
  { page: 'lateral', label: 'Lateral', icon: '<circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="18" r="2.5"/><circle cx="18" cy="6" r="2.5"/><path d="M7.3 7.3 16 16.5M15.5 6h-8M6 8.3 17 16"/>' },
  { page: 'timeline', label: 'Timeline', icon: '<path d="M3 12h18"/><circle cx="7" cy="12" r="1.6"/><circle cx="13" cy="12" r="1.6"/><circle cx="18" cy="12" r="1.6"/>' },
  { page: 'coverage', label: 'Coverage', icon: '<path d="M12 3 4 6v6c0 5 3.5 7.5 8 9 4.5-1.5 8-4 8-9V6l-8-3Z"/><path d="m9 12 2 2 4-4"/>' },
  { page: 'rules', label: 'Rules', icon: '<path d="M4 6h16M4 12h16M4 18h10"/>' },
  { page: 'nodes', label: 'Nodes', icon: '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><circle cx="7" cy="7.5" r="1"/><circle cx="7" cy="16.5" r="1"/>' },
  { page: 'performance', label: 'Performance', icon: '<path d="M3 16a9 9 0 0 1 18 0"/><path d="M12 16l4-4"/><circle cx="12" cy="16" r="1"/>' },
]
const settingsIcon = '<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.6-2-3.4-2.3 1a7 7 0 0 0-1.7-1l-.3-2.4H9.4L9 5a7 7 0 0 0-1.7 1l-2.3-1-2 3.4L5 11a7 7 0 0 0 0 2l-2 1.6 2 3.4 2.3-1a7 7 0 0 0 1.7 1l.4 2.4h4.2l.3-2.4a7 7 0 0 0 1.7-1l2.3 1 2-3.4-2-1.6c.1-.3.1-.7.1-1Z"/>'
const evCount = computed(() => store.allEvents.length)
</script>

<template>
  <aside class="sidebar">
    <div class="brand"><img src="/logo.png" alt="AriGuard" /></div>
    <nav>
      <a v-for="i in items" :key="i.page" :class="{ active: store.page === i.page }" @click.prevent="store.page = i.page">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" v-html="i.icon"></svg>
        {{ i.label }}
        <span v-if="i.page === 'events' && evCount" class="tag">{{ evCount }}</span>
      </a>
      <div class="nav-label">System</div>
      <a :class="{ active: store.page === 'settings' }" @click.prevent="store.page = 'settings'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" v-html="settingsIcon"></svg>
        Settings
      </a>
    </nav>
    <div class="sb-foot">ariguard console<br>{{ store.settings ? 'kernel ' + store.settings.kernel : 'connecting…' }}</div>
  </aside>
</template>
