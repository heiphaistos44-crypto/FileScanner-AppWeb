<script setup lang="ts">
import { ref } from 'vue'

const emit = defineEmits<{ file: [f: File] }>()
defineProps<{ disabled?: boolean }>()

const isDragging = ref(false)
const inputRef = ref<HTMLInputElement | null>(null)

function onDrop(e: DragEvent) {
  e.preventDefault()
  isDragging.value = false
  const f = e.dataTransfer?.files?.[0]
  if (f) emit('file', f)
}

function onPick(e: Event) {
  const input = e.target as HTMLInputElement
  const f = input.files?.[0]
  if (f) emit('file', f)
  input.value = ''
}
</script>

<template>
  <div
    class="dropzone"
    :class="{ dragging: isDragging, disabled }"
    @click="inputRef?.click()"
    @dragover.prevent="isDragging = true"
    @dragenter.prevent="isDragging = true"
    @dragleave.prevent="isDragging = false"
    @drop="onDrop"
  >
    <input ref="inputRef" type="file" hidden @change="onPick" />
    <svg width="42" height="42" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
      <path stroke-linecap="round" stroke-linejoin="round"
        d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.96 11.96 0 0 1 3.6 6 12 12 0 0 0 3 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.6-3.75h-.152c-3.196 0-6.1-1.25-8.25-3.286Z" />
    </svg>
    <p class="title">{{ isDragging ? 'Relâchez le fichier ici' : 'Glissez un fichier ou cliquez pour analyser' }}</p>
    <p class="hint">EXE · DLL · ELF · Mach-O · Scripts · ZIP · Office · PDF · LNK — max 100 MB</p>
  </div>
</template>

<style scoped>
.dropzone {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 10px;
  height: 200px;
  margin-top: 20px;
  border: 2px dashed var(--border);
  border-radius: 16px;
  cursor: pointer;
  color: var(--text-muted);
  transition: all 0.2s;
  user-select: none;
}
.dropzone:hover { border-color: var(--accent); color: var(--text); }
.dropzone.dragging { border-color: var(--accent); background: #3b82f615; transform: scale(1.01); }
.dropzone.disabled { opacity: 0.5; pointer-events: none; }
.title { font-weight: 600; color: var(--text); }
.hint { font-size: 12px; color: var(--text-dim); }
</style>
