<script setup lang="ts">
import Sidebar from './components/Sidebar.vue'
import Topbar from './components/Topbar.vue'
import Overview from './pages/Overview.vue'
import Workloads from './pages/Workloads.vue'
import Events from './pages/Events.vue'
import Incidents from './pages/Incidents.vue'
import ChainModal from './components/ChainModal.vue'
import Rules from './pages/Rules.vue'
import Nodes from './pages/Nodes.vue'
import Settings from './pages/Settings.vue'
import { store } from './api'
</script>

<template>
  <Sidebar />
  <div class="content">
    <Topbar />
    <main>
      <Overview v-if="store.page === 'overview'" />
      <Workloads v-else-if="store.page === 'workloads'" />
      <Events v-else-if="store.page === 'events'" />
      <Incidents v-else-if="store.page === 'incidents'" />
      <Rules v-else-if="store.page === 'rules'" />
      <Nodes v-else-if="store.page === 'nodes'" />
      <Settings v-else />
    </main>
  </div>
  <ChainModal />
</template>
