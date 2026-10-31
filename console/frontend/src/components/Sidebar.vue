<script setup lang="ts">
import { computed } from 'vue'
import { store, type Page } from '../api'

const items: { page: Page; label: string; icon: string }[] = [
  { page: 'overview', label: 'Overview', icon: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>' },
  { page: 'workloads', label: 'Workloads', icon: '<rect x="3" y="4" width="18" height="5" rx="1"/><rect x="3" y="11" width="18" height="5" rx="1"/><rect x="3" y="18" width="18" height="3" rx="1"/>' },
  { page: 'events', label: 'Events', icon: '<path d="M4 18V9m5 9V5m5 13v-6m5 6V8"/>' },
  { page: 'incidents', label: 'Incidents', icon: '<path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 10v4m0 3v.01"/>' },
  { page: 'rules', label: 'Rules', icon: '<path d="M4 6h16M4 12h16M4 18h10"/>' },
  { page: 'nodes', label: 'Nodes', icon: '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><circle cx="7" cy="7.5" r="1"/><circle cx="7" cy="16.5" r="1"/>' },
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
