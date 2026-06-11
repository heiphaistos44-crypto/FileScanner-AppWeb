<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{ title: string; count?: number; defaultOpen?: boolean }>()
const open = ref(props.defaultOpen ?? false)
</script>

<template>
  <div class="card">
    <div class="card-header" @click="open = !open">
      <span>{{ title }}</span>
      <span style="display: flex; align-items: center; gap: 8px">
        <span v-if="count !== undefined" class="badge-count">{{ count }}</span>
        <span style="font-size: 11px; color: var(--text-dim)">{{ open ? '▲' : '▼' }}</span>
      </span>
    </div>
    <div v-if="open" class="card-body">
      <slot />
    </div>
  </div>
</template>
