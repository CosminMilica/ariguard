<script setup lang="ts">
import { store, fmtWindow, isKill } from '../api'
</script>

<template>
  <section class="card">
    <div class="hd"><h2>Rules</h2><span class="c">compiled bundle · {{ store.rules.length }} rules</span></div>
    <div class="scroll">
      <table>
        <thead><tr><th>Rule</th><th>Scope</th><th>States</th><th>Window</th><th>Terminal action</th><th>Hits</th></tr></thead>
        <tbody>
          <tr v-if="!store.rules.length"><td colspan="6" class="empty">No rules registered yet.</td></tr>
          <tr v-for="r in store.rules" :key="r.name">
            <td class="mono">{{ r.name }}</td><td class="mono dim">{{ r.scope }}</td><td class="mono">{{ r.num_states }}</td>
            <td class="mono">{{ fmtWindow(r.window_ns) }}</td>
            <td><span class="act" :class="{ kill: isKill(r.terminal_action) }">{{ isKill(r.terminal_action) ? 'KILL' : r.terminal_action }}</span></td>
            <td class="mono">{{ r.hits }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
