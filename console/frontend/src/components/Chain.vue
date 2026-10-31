<script setup lang="ts">
import { computed } from 'vue'
import { type ChainStep, store, clockNs, isKill, pickChainPod } from '../api'

const props = defineProps<{ pod?: string; chain?: ChainStep[]; bare?: boolean }>()
const pod = computed(() => props.pod ?? pickChainPod())
const steps = computed(() => (props.chain ?? store.chain).map(s => ({
  ...s,
  cls: isKill(s.action) && s.enforced ? 'kill' : s.state !== 'normal' ? 'hit' : '',
})))
</script>

<template>
  <div :class="bare ? '' : 'card'">
    <div v-if="!bare" class="hd"><h2>Attack chain</h2><span class="c">{{ pod || 'no pod selected' }}</span></div>
    <div :class="bare ? '' : 'bd'">
      <div v-if="!steps.length" class="empty">{{ pod ? 'No chain recorded for this pod.' : 'No compromised workloads yet.' }}</div>
      <div v-else class="chain">
        <div v-for="(s, i) in steps" :key="i" class="step" :class="s.cls">
          <div class="rail"><span class="pt"></span><span class="ln"></span></div>
          <div>
            <span class="ts">{{ clockNs(s.ts_ns) }}</span>
            <div class="st2">{{ s.state }}</div>
            <div class="sc">{{ s.event }}<template v-if="s.action && s.action !== 'observe'"> · <b>{{ s.action }}{{ s.enforced ? '' : ' (detect)' }}</b></template></div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
