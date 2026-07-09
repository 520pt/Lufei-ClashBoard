<template>
  <div class="relative flex size-full min-h-0 flex-col overflow-hidden">
    <div class="min-h-0 flex-1 overflow-x-hidden overflow-y-auto">
      <div
        class="grid grid-cols-1 gap-3 p-3"
        :style="padding"
      >
        <CustomRules />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import CustomRules from '@/components/rules/CustomRules.vue'
import { usePaddingForViews } from '@/composables/paddingViews'

const { padding } = usePaddingForViews({
  offsetTop: 0,
  offsetBottom: 8,
})
</script>
