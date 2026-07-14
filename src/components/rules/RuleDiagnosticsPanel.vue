<template>
  <div class="card app-card-padding gap-3">
    <div class="flex items-center justify-between gap-2">
      <div>
        <div class="font-semibold">规则健康中心</div>
        <div class="text-base-content/60 text-xs">规则冲突和运行状态集中检查。</div>
      </div>
      <button
        class="btn btn-sm"
        type="button"
        @click="toggleDiagnosticsCollapsed"
      >
        {{ useRuleDiagnosticsCollapsed ? '展开' : '收起' }}
      </button>
    </div>
  </div>

  <div
    v-if="!useRuleDiagnosticsCollapsed"
    class="grid gap-3 xl:grid-cols-2"
  >
    <div class="card app-card-padding gap-3">
      <div class="flex items-center justify-between gap-2">
        <div>
          <div class="font-semibold">规则冲突中心</div>
          <div class="text-base-content/60 text-xs">
            检查 LuFei、OpenClash、Nikki 自定义规则里是否有同域名/IP 重复。
          </div>
        </div>
        <button
          class="btn btn-sm"
          type="button"
          :disabled="conflictLoading"
          @click="loadConflictReport"
        >
          检查
        </button>
      </div>
      <div
        v-if="conflictReport?.warning"
        class="alert alert-warning py-2 text-xs"
      >
        {{ conflictReport.warning }}
      </div>
      <div
        class="rounded-box border-base-300 bg-base-200 flex items-center justify-between gap-3 border p-3"
      >
        <div>
          <div class="text-sm font-semibold">当前冲突</div>
          <div class="text-base-content/60 text-xs">同一个规则类型和值只应该保留在一个来源里。</div>
        </div>
        <div
          class="badge"
          :class="conflictReport?.count ? 'badge-warning' : 'badge-success'"
        >
          {{ conflictReport?.count || 0 }} 组
        </div>
      </div>
      <div
        v-if="conflictReport?.conflicts.length"
        class="flex max-h-72 flex-col gap-2 overflow-auto pr-1"
      >
        <div
          v-for="conflict in conflictReport.conflicts"
          :key="conflict.key"
          class="bg-base-200 rounded-box border-base-300 border p-3 text-xs"
        >
          <div class="font-semibold">{{ conflict.type }}：{{ conflict.value }}</div>
          <div class="mt-2 flex flex-col gap-1">
            <div
              v-for="source in conflict.sources"
              :key="`${conflict.key}-${source.source}-${source.raw}`"
              class="bg-base-100 rounded-box px-2 py-1"
            >
              <span class="text-primary font-semibold">{{ source.source || '未知来源' }}</span>
              <span class="font-mono break-all">：{{ source.raw }}</span>
            </div>
          </div>
        </div>
      </div>
      <div
        v-else
        class="text-base-content/60 rounded-box bg-base-200 p-3 text-sm"
      >
        暂未发现冲突。
      </div>
    </div>

    <div class="card app-card-padding gap-3">
      <div class="flex items-center justify-between gap-2">
        <div>
          <div class="font-semibold">健康检查</div>
          <div class="text-base-content/60 text-xs">
            检查持久化、规则数量、SSH 配置和 YAML 写入状态。
          </div>
        </div>
        <button
          class="btn btn-sm"
          type="button"
          :disabled="diagnosticsLoading"
          @click="loadDiagnostics"
        >
          诊断
        </button>
      </div>
      <div
        v-if="diagnostics?.conflictWarning"
        class="alert alert-warning py-2 text-xs"
      >
        {{ diagnostics.conflictWarning }}
      </div>
      <div class="grid gap-2">
        <div
          v-for="check in diagnostics?.checks || []"
          :key="check.key"
          class="bg-base-200 rounded-box border-base-300 flex items-start justify-between gap-3 border p-3"
        >
          <div class="min-w-0">
            <div class="text-sm font-semibold">{{ check.label }}</div>
            <div class="text-base-content/60 mt-1 text-xs break-all">{{ check.message }}</div>
          </div>
          <div
            class="badge shrink-0"
            :class="
              check.status === 'ok'
                ? 'badge-success'
                : check.status === 'warning'
                  ? 'badge-warning'
                  : 'badge-error'
            "
          >
            {{ check.status === 'ok' ? '正常' : check.status === 'warning' ? '注意' : '错误' }}
          </div>
        </div>
        <div
          v-if="!diagnostics?.checks.length"
          class="text-base-content/60 rounded-box bg-base-200 p-3 text-sm"
        >
          点击“诊断”开始检查。
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  fetchCustomRuleConflictsAPI,
  fetchLufeiDiagnosticsAPI,
  type CustomRuleConflictPayload,
  type LufeiDiagnosticsPayload,
} from '@/api'
import { showNotification } from '@/helper/notification'
import { useRuleDiagnosticsCollapsed } from '@/store/settings'
import { onMounted, ref } from 'vue'

const conflictReport = ref<CustomRuleConflictPayload | null>(null)
const diagnostics = ref<LufeiDiagnosticsPayload | null>(null)
const conflictLoading = ref(false)
const diagnosticsLoading = ref(false)

const toggleDiagnosticsCollapsed = () => {
  useRuleDiagnosticsCollapsed.value = !useRuleDiagnosticsCollapsed.value
}

const loadConflictReport = async () => {
  conflictLoading.value = true

  try {
    conflictReport.value = await fetchCustomRuleConflictsAPI()
  } catch (error) {
    showNotification({
      content: error instanceof Error ? error.message : String(error),
      type: 'alert-error',
    })
  } finally {
    conflictLoading.value = false
  }
}

const loadDiagnostics = async () => {
  diagnosticsLoading.value = true

  try {
    diagnostics.value = await fetchLufeiDiagnosticsAPI()
  } catch (error) {
    showNotification({
      content: error instanceof Error ? error.message : String(error),
      type: 'alert-error',
    })
  } finally {
    diagnosticsLoading.value = false
  }
}

onMounted(() => {
  loadConflictReport()
  loadDiagnostics()
})
</script>
