<template>
  <div class="flex flex-col gap-3">
    <div class="card app-card-padding gap-4">
      <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div class="min-w-0">
          <div class="flex flex-wrap items-center gap-2">
            <div class="text-xl font-semibold">自定义规则集</div>
            <div class="badge badge-primary badge-sm">ziyong.list</div>
            <div class="badge badge-ghost badge-sm">
              {{ customRules?.rules.length || 0 }} 条规则
            </div>
          </div>
          <div class="text-base-content/70 mt-1 text-sm">
            在这里维护自己的域名、网址和 IP，保存后会立即更新到规则集地址。
          </div>
        </div>
        <button
          class="btn btn-sm"
          type="button"
          :disabled="loading"
          @click="loadCustomRules"
        >
          刷新
        </button>
      </div>

      <div
        v-if="errorMessage"
        class="alert alert-error py-2 text-sm"
      >
        {{ errorMessage }}
      </div>

      <div class="grid gap-3 xl:grid-cols-[1.1fr_0.9fr]">
        <div class="bg-base-200 rounded-box flex min-w-0 flex-col gap-2 p-3">
          <div class="flex items-center justify-between gap-2">
            <div class="text-sm font-semibold">规则地址</div>
            <button
              class="btn btn-xs"
              type="button"
              @click="copyText(customRules?.ruleUrl || '')"
            >
              复制
            </button>
          </div>
          <button
            class="bg-base-100 rounded-box border-base-300 hover:border-primary w-full border p-3 text-left font-mono text-xs break-all transition-colors"
            type="button"
            @click="copyText(customRules?.ruleUrl || '')"
          >
            {{ customRules?.ruleUrl || '-' }}
          </button>
          <div class="text-base-content/60 text-xs">
            把这个地址填到 YAML 的 <code>rule-providers</code> 里，OpenClash 会读取这里的规则。
          </div>
        </div>

        <form
          class="bg-base-200 rounded-box grid gap-2 p-3 md:grid-cols-[1fr_auto]"
          @submit.prevent="handleSaveSettings"
        >
          <label class="form-control min-w-0">
            <span class="label-text mb-1 text-xs">代理策略名称</span>
            <input
              v-model.trim="policyGroup"
              class="input input-bordered input-sm"
              placeholder="路飞 或 lufei"
              required
            />
          </label>
          <button
            class="btn btn-sm self-end"
            type="submit"
            :disabled="submitting"
          >
            保存名称
          </button>
          <div class="text-base-content/60 text-xs md:col-span-2">
            能显示中文就用中文，默认“路飞”；如果 OpenClash 中中文显示异常，就改成拼音。
          </div>
        </form>
      </div>
    </div>

    <div class="card app-card-padding gap-3">
      <div class="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
        <div>
          <div class="font-semibold">快速添加规则</div>
          <div class="text-base-content/60 text-xs">
            支持 example.com、https://example.com/path、1.2.3.4、10.0.0.0/8。
          </div>
        </div>
      </div>

      <form
        class="grid gap-2 md:grid-cols-[1fr_180px_auto]"
        @submit.prevent="handleAddRule"
      >
        <input
          v-model.trim="target"
          class="input input-bordered input-sm"
          placeholder="输入域名、网址、IP 或 CIDR"
          required
        />
        <select
          v-model="kind"
          class="select select-bordered select-sm"
        >
          <option value="auto">自动识别</option>
          <option value="domain_suffix">DOMAIN-SUFFIX</option>
          <option value="domain">DOMAIN</option>
          <option value="ip_cidr">IP-CIDR</option>
          <option value="raw">原始规则</option>
        </select>
        <button
          class="btn btn-primary btn-sm"
          type="submit"
          :disabled="submitting"
        >
          添加规则
        </button>
      </form>
    </div>

    <div class="card app-card-padding gap-3">
      <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div>
          <div class="font-semibold">YAML 添加说明</div>
          <div class="text-base-content/60 text-xs">
            可以复制下面三段手动添加，也可以通过规则源 SSH 一键写入当前使用的 YAML。
          </div>
        </div>
        <button
          class="btn btn-primary btn-sm"
          type="button"
          :disabled="submitting || !customRules?.ruleUrl"
          @click="applyDialogVisible = true"
        >
          一键写入当前 YAML
        </button>
      </div>

      <div class="grid gap-2 lg:grid-cols-3">
        <div
          v-for="snippet in snippets"
          :key="snippet.title"
          class="bg-base-200 rounded-box flex min-w-0 flex-col gap-2 p-3 text-xs"
        >
          <div class="flex items-center justify-between gap-2">
            <div class="font-semibold">{{ snippet.title }}</div>
            <button
              class="btn btn-xs"
              type="button"
              @click="copyText(snippet.value)"
            >
              复制
            </button>
          </div>
          <button
            class="bg-base-100 rounded-box border-base-300 hover:border-primary min-h-16 border p-2 text-left font-mono break-all transition-colors"
            type="button"
            @click="copyText(snippet.value)"
          >
            {{ snippet.value || '-' }}
          </button>
        </div>
      </div>
    </div>

    <div class="card app-card-padding gap-3">
      <div class="flex items-center justify-between gap-2">
        <div>
          <div class="font-semibold">当前自定义规则</div>
          <div class="text-base-content/60 text-xs">
            共 {{ customRules?.rules.length || 0 }} 条，删除前会再次确认。
          </div>
        </div>
      </div>

      <div
        v-if="!customRules?.rules.length"
        class="text-base-content/60 rounded-box border-base-300 border border-dashed p-4 text-sm"
      >
        暂无自定义规则。可以先添加 <code>example.com</code> 或 <code>1.2.3.4</code> 测试。
      </div>

      <div
        v-else
        class="flex flex-col gap-2"
      >
        <div
          v-for="rule in customRules.rules"
          :key="rule"
          class="bg-base-200 rounded-box flex items-center justify-between gap-3 p-3"
        >
          <code class="min-w-0 flex-1 text-xs break-all">{{ rule }}</code>
          <button
            class="btn btn-error btn-xs shrink-0"
            type="button"
            :disabled="submitting"
            @click="askDeleteRule(rule)"
          >
            删除
          </button>
        </div>
      </div>
    </div>

    <DialogWrapper
      v-model="deleteDialogVisible"
      title="确认删除规则"
      box-class="max-w-lg"
    >
      <div class="flex flex-col gap-4 text-sm">
        <div>确定要删除这条自定义规则吗？</div>
        <code class="bg-base-200 rounded-box p-3 text-xs break-all">{{ pendingDeleteRule }}</code>
        <div class="flex justify-end gap-2">
          <button
            class="btn btn-sm"
            type="button"
            @click="deleteDialogVisible = false"
          >
            取消
          </button>
          <button
            class="btn btn-error btn-sm"
            type="button"
            :disabled="submitting"
            @click="confirmDeleteRule"
          >
            删除
          </button>
        </div>
      </div>
    </DialogWrapper>

    <DialogWrapper
      v-model="applyDialogVisible"
      title="写入当前 OpenClash YAML"
      box-class="max-w-xl"
    >
      <div class="flex flex-col gap-4 text-sm">
        <div>
          将通过后端配置里的规则源 SSH 连接 OpenWrt，自动检测当前正在使用的
          YAML，并写入自定义规则集。
        </div>
        <div class="bg-base-200 rounded-box flex flex-col gap-2 p-3">
          <div class="text-base-content/70 text-xs">规则地址</div>
          <code class="text-xs break-all">{{ customRules?.ruleUrl || '-' }}</code>
        </div>
        <div class="text-base-content/60 text-xs">
          写入前会在 OpenWrt 上自动备份原 YAML；如果已经存在相同配置，不会重复添加。
        </div>
        <div class="flex justify-end gap-2">
          <button
            class="btn btn-sm"
            type="button"
            @click="applyDialogVisible = false"
          >
            取消
          </button>
          <button
            class="btn btn-primary btn-sm"
            type="button"
            :disabled="submitting"
            @click="confirmApplyToYaml"
          >
            确认写入
          </button>
        </div>
      </div>
    </DialogWrapper>
  </div>
</template>

<script setup lang="ts">
import {
  addCustomRuleAPI,
  applyCustomRuleToActiveYamlAPI,
  deleteCustomRuleAPI,
  fetchCustomRulesAPI,
  reloadConfigsAPI,
  updateCustomRulesSettingsAPI,
  type CustomRulesPayload,
} from '@/api'
import DialogWrapper from '@/components/common/DialogWrapper.vue'
import { showNotification } from '@/helper/notification'
import { fetchProxies } from '@/store/proxies'
import { fetchRules } from '@/store/rules'
import { computed, onMounted, ref } from 'vue'

const customRules = ref<CustomRulesPayload | null>(null)
const target = ref('')
const kind = ref('auto')
const policyGroup = ref('路飞')
const loading = ref(false)
const submitting = ref(false)
const errorMessage = ref('')
const deleteDialogVisible = ref(false)
const applyDialogVisible = ref(false)
const pendingDeleteRule = ref('')

const snippets = computed(() => [
  {
    title: 'proxy-groups',
    value: customRules.value?.snippets.proxyGroupLine || '',
  },
  {
    title: 'rule-providers',
    value: customRules.value?.snippets.providerLine || '',
  },
  {
    title: 'rules',
    value: customRules.value?.snippets.ruleLine || '',
  },
])

const loadCustomRules = async () => {
  loading.value = true
  errorMessage.value = ''

  try {
    customRules.value = await fetchCustomRulesAPI()
    policyGroup.value = customRules.value.settings.policyGroup
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : String(error)
  } finally {
    loading.value = false
  }
}

const copyText = async (value: string) => {
  if (!value) return

  await navigator.clipboard.writeText(value)
  showNotification({ content: '已复制到剪切板', type: 'alert-success', timeout: 1800 })
}

const handleAddRule = async () => {
  submitting.value = true

  try {
    const result = await addCustomRuleAPI(target.value, kind.value)
    target.value = ''
    showNotification({
      content: result.added ? `已添加：${result.rule}` : `已存在：${result.rule}`,
      type: result.added ? 'alert-success' : 'alert-info',
      timeout: 2200,
    })
    await loadCustomRules()
  } catch (error) {
    showNotification({
      content: error instanceof Error ? error.message : String(error),
      type: 'alert-error',
    })
  } finally {
    submitting.value = false
  }
}

const askDeleteRule = (rule: string) => {
  pendingDeleteRule.value = rule
  deleteDialogVisible.value = true
}

const confirmDeleteRule = async () => {
  if (!pendingDeleteRule.value) return

  submitting.value = true

  try {
    const rule = pendingDeleteRule.value
    await deleteCustomRuleAPI(rule)
    deleteDialogVisible.value = false
    pendingDeleteRule.value = ''
    showNotification({ content: `已删除：${rule}`, type: 'alert-success', timeout: 2200 })
    await loadCustomRules()
  } catch (error) {
    showNotification({
      content: error instanceof Error ? error.message : String(error),
      type: 'alert-error',
    })
  } finally {
    submitting.value = false
  }
}

const handleSaveSettings = async () => {
  submitting.value = true

  try {
    await updateCustomRulesSettingsAPI({ policyGroup: policyGroup.value })
    showNotification({ content: `已保存代理策略名称：${policyGroup.value}`, type: 'alert-success' })
    await loadCustomRules()
  } catch (error) {
    showNotification({
      content: error instanceof Error ? error.message : String(error),
      type: 'alert-error',
    })
  } finally {
    submitting.value = false
  }
}

const confirmApplyToYaml = async () => {
  if (!customRules.value?.ruleUrl) return

  submitting.value = true

  try {
    const result = await applyCustomRuleToActiveYamlAPI(customRules.value.ruleUrl)
    applyDialogVisible.value = false

    showNotification({
      content: result.changed
        ? `已写入当前 YAML：${result.configPath}，备份：${result.backupPath}，正在重新加载配置...`
        : `当前 YAML 已经包含自定义规则：${result.configPath}，正在重新加载配置...`,
      type: result.changed ? 'alert-success' : 'alert-info',
      timeout: 6000,
    })

    await reloadConfigsAPI()
    await Promise.allSettled([fetchProxies(), fetchRules()])

    showNotification({
      content: '配置已重新加载，策略组和规则列表已刷新',
      type: 'alert-success',
      timeout: 3600,
    })
  } catch (error) {
    showNotification({
      content: error instanceof Error ? error.message : String(error),
      type: 'alert-error',
      timeout: 6000,
    })
  } finally {
    submitting.value = false
  }
}

onMounted(loadCustomRules)
</script>
