<script setup lang="ts">
import { store, nodeOk, fmtNum } from '../api'
</script>

<template>
  <section class="card">
    <div class="hd"><h2>Nodes</h2><span class="c">DaemonSet · {{ store.nodes.length }} agents</span></div>
    <div class="scroll">
      <table>
        <thead><tr><th>Node</th><th>Kernel</th><th>Hooks</th><th>Attached</th><th>Events/s</th><th>Status</th></tr></thead>
        <tbody>
          <tr v-if="!store.nodes.length"><td colspan="6" class="empty">No agents have registered yet.</td></tr>
          <tr v-for="n in store.nodes" :key="n.node">
            <td class="mono">{{ n.node }}</td><td class="mono dim">{{ n.kernel }}</td>
            <td class="mono">{{ n.hooks_attached }}/{{ n.hooks_total }}</td>
            <td><span class="bar"><i :style="{ width: (n.hooks_total ? (n.hooks_attached / n.hooks_total) * 100 : 0) + '%' }"></i></span></td>
            <td class="mono">{{ fmtNum(n.events_per_sec) }}</td>
            <td><span class="st" :class="nodeOk(n.status) ? 'normal' : 'suspicious'">{{ n.status }}</span></td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
