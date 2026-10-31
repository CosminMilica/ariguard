<script setup lang="ts">
import { onMounted, onBeforeUnmount } from 'vue'
import Chain from './Chain.vue'
import { store, closeChainModal } from '../api'

const key = (e: KeyboardEvent) => { if (e.key === 'Escape' && store.chainModalPod) closeChainModal() }
onMounted(() => document.addEventListener('keydown', key))
onBeforeUnmount(() => document.removeEventListener('keydown', key))
</script>

<template>
  <div v-if="store.chainModalPod" class="modal-bg" @click="closeChainModal">
    <div class="modal wide" @click.stop>
      <div class="mhd">
        <h2 class="mono">{{ store.chainModalPod }}</h2>
        <button class="btn" aria-label="Close" @click="closeChainModal">✕</button>
      </div>
      <div class="mbd"><Chain bare :pod="store.chainModalPod" :chain="store.modalChain" /></div>
    </div>
  </div>
</template>
