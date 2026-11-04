<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { store } from '../api'
import { NAV, sectionOf } from '../nav'

const settingsIcon = '<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.6-2-3.4-2.3 1a7 7 0 0 0-1.7-1l-.3-2.4H9.4L9 5a7 7 0 0 0-1.7 1l-2.3-1-2 3.4L5 11a7 7 0 0 0 0 2l-2 1.6 2 3.4 2.3-1a7 7 0 0 0 1.7 1l.4 2.4h4.2l.3-2.4a7 7 0 0 0 1.7-1l2.3 1 2-3.4-2-1.6c.1-.3.1-.7.1-1Z"/>'
const activeSection = computed(() => sectionOf(store.page).key)
const evCount = computed(() => store.allEvents.length)

// expanded is the section whose sub-pages are shown. Starts on the active section; navigating to a
// page in another section opens that one.
const expanded = ref(activeSection.value)
watch(activeSection, (k) => { expanded.value = k })

// Clicking a section: if it is already expanded, collapse its sub-menu; otherwise expand it and
// enter its first page (unless the current page is already inside it).
function openSection(key: string) {
  const sec = NAV.find(s => s.key === key)!
  if (sec.pages.length > 1 && expanded.value === key) { expanded.value = '' ; return }
  expanded.value = key
  if (!sec.pages.some(p => p.page === store.page)) store.page = sec.pages[0].page
}
</script>

<template>
  <aside class="sidebar">
    <div class="brand"><img src="/logo.png" alt="AriGuard" /></div>
    <nav>
      <template v-for="s in NAV" :key="s.key">
        <a :class="{ active: activeSection === s.key }" @click.prevent="openSection(s.key)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" v-html="s.icon"></svg>
          {{ s.label }}
          <span v-if="s.key === 'activity' && evCount" class="tag">{{ evCount }}</span>
        </a>
        <div v-if="expanded === s.key && s.pages.length > 1" class="subnest">
          <a v-for="p in s.pages" :key="p.page" class="subitem"
            :class="{ active: store.page === p.page }" @click.prevent="store.page = p.page">
            {{ p.label }}
          </a>
        </div>
      </template>
      <div class="nav-label">System</div>
      <a :class="{ active: store.page === 'settings' }" @click.prevent="store.page = 'settings'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" v-html="settingsIcon"></svg>
        Settings
      </a>
    </nav>
    <div class="sb-foot">ariguard console<br>{{ store.settings ? 'kernel ' + store.settings.kernel : 'connecting…' }}</div>
  </aside>
</template>

<style scoped>
/* Nested sub-pages under the active section — a guide rail instead of a top-of-page tab bar. */
.subnest { display:flex; flex-direction:column; gap:1px; margin:1px 0 4px 21px; padding-left:7px; border-left:1px solid var(--border-2); }
.subitem { padding:5px 9px; border-radius:6px; color:var(--muted); font-size:12.5px; cursor:pointer; text-decoration:none; }
.subitem:hover { background:var(--hover); color:var(--fg-2); }
.subitem.active { color:var(--fg); font-weight:550; background:var(--sel); }
</style>
