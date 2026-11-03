<script setup lang="ts">
import { computed } from 'vue'
import { store } from '../api'
import { sectionOf } from '../nav'

// Sub-tabs for the current section; hidden for single-page sections and Settings.
const section = computed(() => sectionOf(store.page))
const show = computed(() => section.value.pages.length > 1 && store.page !== 'settings')
</script>

<template>
  <nav v-if="show" class="subnav">
    <button v-for="p in section.pages" :key="p.page" class="subtab"
      :class="{ on: store.page === p.page }" @click="store.page = p.page">
      {{ p.label }}
    </button>
  </nav>
</template>

<style scoped>
.subnav { display:flex; gap:4px; margin-bottom:16px; border-bottom:1px solid var(--border); }
.subtab {
  font-family:var(--sans); font-size:12.5px; color:var(--muted);
  background:transparent; border:0; border-bottom:2px solid transparent;
  padding:7px 12px; margin-bottom:-1px; cursor:pointer;
}
.subtab:hover { color:var(--fg); }
.subtab.on { color:var(--fg); border-bottom-color:var(--teal); }
</style>
