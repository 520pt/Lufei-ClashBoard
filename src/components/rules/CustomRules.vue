<template>
  <div class="flex flex-col gap-3">
    <div class="grid gap-3 lg:grid-cols-2">
      <div class="card app-card-padding gap-4">
        <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <div class="text-xl font-semibold">自定义规则集</div>
              <div class="badge badge-primary badge-sm">ziyong.list</div>
              <div class="badge badge-success badge-sm">ziyong-direct.list</div>
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

        <div class="grid gap-3">
          <div class="bg-base-200 rounded-box flex min-w-0 flex-col gap-2 p-3">
            <div class="flex items-center justify-between gap-2">
              <div class="text-sm font-semibold">规则地址</div>
              <button
                class="btn btn-primary btn-xs"
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
              <span class="text-primary mr-2 font-sans">代理</span>{{ customRules?.ruleUrl || '-' }}
            </button>
            <button
              class="bg-base-100 rounded-box border-base-300 hover:border-primary w-full border p-3 text-left font-mono text-xs break-all transition-colors"
              type="button"
              @click="copyText(customRules?.directRuleUrl || '')"
            >
              <span class="text-success mr-2 font-sans">直连</span
              >{{ customRules?.directRuleUrl || '-' }}
            </button>
            <div class="text-base-content/60 text-xs">
              把这个地址填到 YAML 的 <code>rule-providers</code> 里，OpenClash 会读取这里的规则。
            </div>
          </div>

          <form
            class="bg-base-200 rounded-box grid gap-2 p-3 md:grid-cols-[1fr_1fr_auto]"
            @submit.prevent="handleSaveSettings"
          >
            <div class="text-sm font-semibold md:col-span-3">自定义</div>
            <label class="form-control min-w-0">
              <span class="label-text mb-1 text-xs">代理</span>
              <input
                v-model.trim="policyGroup"
                class="input input-bordered input-sm"
                placeholder="自定义-代理 或 zidingyi-daili"
                required
              />
            </label>
            <label class="form-control min-w-0">
              <span class="label-text mb-1 text-xs">直连</span>
              <input
                v-model.trim="directPolicyGroup"
                class="input input-bordered input-sm"
                placeholder="自定义-直连 或 zidingyi-zhilian"
                required
              />
            </label>
            <button
              class="btn btn-primary btn-sm self-end"
              type="submit"
              :disabled="submitting"
            >
              保存名称
            </button>
            <div class="text-base-content/60 text-xs md:col-span-3">
              默认写入“自定义-代理”和“自定义-直连”；如果 OpenClash 中中文显示异常，就改成拼音。
            </div>
          </form>
        </div>
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

        <div class="grid gap-2">
          <div
            v-for="snippet in snippets"
            :key="snippet.title"
            class="bg-base-200 rounded-box flex min-w-0 flex-col gap-2 p-3 text-xs"
          >
            <div class="flex items-center justify-between gap-2">
              <div class="font-semibold">{{ snippet.title }}</div>
              <button
                class="btn btn-primary btn-xs"
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
        class="grid gap-2 md:grid-cols-[minmax(0,1fr)_180px]"
        @submit.prevent="handleAddRule"
      >
        <div class="join min-w-0">
          <button
            class="btn btn-sm join-item w-20 shrink-0"
            :class="targetPolicy === 'proxy' ? 'btn-primary' : 'btn-outline'"
            type="button"
            @click="targetPolicy = 'proxy'"
          >
            代理
          </button>
          <button
            class="btn btn-sm join-item w-20 shrink-0"
            :class="targetPolicy === 'direct' ? 'btn-success' : 'btn-outline'"
            type="button"
            @click="targetPolicy = 'direct'"
          >
            直连
          </button>
          <input
            v-model.trim="target"
            class="input input-bordered input-sm join-item min-w-0 flex-1"
            placeholder="输入域名、网址、IP 或 CIDR"
            required
          />
          <button
            class="btn btn-primary btn-sm"
            type="submit"
            :disabled="submitting"
          >
            添加规则
          </button>
        </div>
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
      </form>
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
          v-for="entry in customRules.rules"
          :key="`${entry.policy}:${entry.rule}`"
          class="bg-base-200 rounded-box flex items-center justify-between gap-3 p-3"
        >
          <div class="flex min-w-0 flex-1 items-center gap-2">
            <div
              class="badge badge-sm shrink-0"
              :class="entry.policy === 'direct' ? 'badge-success' : 'badge-primary'"
            >
              {{ getPolicyLabel(entry.policy) }}
            </div>
            <code class="min-w-0 text-xs break-all">{{ entry.rule }}</code>
          </div>
          <button
            class="btn btn-error btn-xs shrink-0"
            type="button"
            :disabled="submitting"
            @click="askDeleteRule(entry)"
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
        <div class="bg-base-200 rounded-box flex flex-col gap-2 p-3">
          <div class="badge badge-sm w-fit">
            {{ pendingDeleteEntry ? getPolicyLabel(pendingDeleteEntry.policy) : '-' }}
          </div>
          <code class="text-xs break-all">{{ pendingDeleteEntry?.rule || '-' }}</code>
        </div>
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
          YAML，并写入代理和直连两套自定义规则集。
        </div>
        <div class="bg-base-200 rounded-box flex flex-col gap-2 p-3">
          <div class="text-base-content/70 text-xs">代理规则地址</div>
          <code class="text-xs break-all">{{ customRules?.ruleUrl || '-' }}</code>
          <div class="text-base-content/70 mt-2 text-xs">直连规则地址</div>
          <code class="text-xs break-all">{{ customRules?.directRuleUrl || '-' }}</code>
        </div>
        <div class="text-base-content/60 text-xs">
          写入前会在 OpenWrt 上自动备份原 YAML；如果已存在旧配置，会自动补齐或更新为双策略。
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
  updateRuleProviderAPI,
  type CustomRuleEntry,
  type CustomRulePolicy,
  type CustomRulesPayload,
} from '@/api'
import DialogWrapper from '@/components/common/DialogWrapper.vue'
import {
  CUSTOM_DIRECT_PROXY_GROUP_ICON,
  CUSTOM_PROXY_GROUP_ICON,
} from '@/helper/autoImportSettings'
import { showNotification } from '@/helper/notification'
import { fetchProxies } from '@/store/proxies'
import { fetchRules } from '@/store/rules'
import { iconReflectList } from '@/store/settings'
import { v4 as uuid } from 'uuid'
import { computed, onMounted, ref } from 'vue'

const customRules = ref<CustomRulesPayload | null>(null)
const target = ref('')
const kind = ref('auto')
const targetPolicy = ref<CustomRulePolicy>('proxy')
const policyGroup = ref('自定义-代理')
const directPolicyGroup = ref('自定义-直连')
const loading = ref(false)
const submitting = ref(false)
const errorMessage = ref('')
const deleteDialogVisible = ref(false)
const applyDialogVisible = ref(false)
const pendingDeleteEntry = ref<CustomRuleEntry | null>(null)

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
    directPolicyGroup.value = customRules.value.settings.directPolicyGroup
    ensureCustomPolicyGroupIcon(policyGroup.value, CUSTOM_PROXY_GROUP_ICON)
    ensureCustomPolicyGroupIcon(directPolicyGroup.value, CUSTOM_DIRECT_PROXY_GROUP_ICON)
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

const sleep = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms))

const getPolicyLabel = (policy: CustomRulePolicy) => (policy === 'direct' ? '直连' : '代理')

const refreshRuntimeRulesAndProxies = async () => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const results = await Promise.allSettled([fetchProxies(), fetchRules()])

    if (results.every((result) => result.status === 'fulfilled')) {
      return true
    }

    await sleep(3000)
  }

  return false
}

const ensureCustomPolicyGroupIcon = (name: string, icon: string) => {
  const policyGroupName = name.trim()

  if (!policyGroupName) return

  const existing = iconReflectList.value.find((item) => item.name === policyGroupName)

  if (existing) {
    existing.icon = icon
    return
  }

  iconReflectList.value.push({
    name: policyGroupName,
    icon,
    uuid: uuid(),
  })
}

const refreshCustomRuleProvider = async (policy: CustomRulePolicy) => {
  const providerName =
    policy === 'direct'
      ? customRules.value?.settings.directProviderName
      : customRules.value?.settings.providerName

  if (!providerName) return false

  try {
    await updateRuleProviderAPI(providerName)
    await fetchRules()
    return true
  } catch (error) {
    showNotification({
      content: `规则已保存，但${getPolicyLabel(policy)}规则源暂未刷新：${
        error instanceof Error ? error.message : String(error)
      }`,
      type: 'alert-warning',
      timeout: 5000,
    })
    return false
  }
}

const handleAddRule = async () => {
  submitting.value = true

  try {
    const selectedPolicy = targetPolicy.value
    const result = await addCustomRuleAPI(target.value, kind.value, selectedPolicy)
    target.value = ''
    await loadCustomRules()
    const refreshed = await refreshCustomRuleProvider(selectedPolicy)
    showNotification({
      content: result.added
        ? `已添加到${getPolicyLabel(selectedPolicy)}：${result.rule}${refreshed ? '，规则源已刷新' : ''}`
        : `${getPolicyLabel(selectedPolicy)}已存在：${result.rule}${
            refreshed ? '，规则源已刷新' : ''
          }`,
      type: result.added ? 'alert-success' : 'alert-info',
      timeout: 2200,
    })
  } catch (error) {
    showNotification({
      content: error instanceof Error ? error.message : String(error),
      type: 'alert-error',
    })
  } finally {
    submitting.value = false
  }
}

const askDeleteRule = (entry: CustomRuleEntry) => {
  pendingDeleteEntry.value = entry
  deleteDialogVisible.value = true
}

const confirmDeleteRule = async () => {
  if (!pendingDeleteEntry.value) return

  submitting.value = true

  try {
    const entry = pendingDeleteEntry.value
    await deleteCustomRuleAPI(entry.rule, entry.policy)
    deleteDialogVisible.value = false
    pendingDeleteEntry.value = null
    await loadCustomRules()
    const refreshed = await refreshCustomRuleProvider(entry.policy)
    showNotification({
      content: `已删除${getPolicyLabel(entry.policy)}规则：${entry.rule}${
        refreshed ? '，规则源已刷新' : ''
      }`,
      type: 'alert-success',
      timeout: 2200,
    })
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
    await updateCustomRulesSettingsAPI({
      policyGroup: policyGroup.value,
      directPolicyGroup: directPolicyGroup.value,
    })
    ensureCustomPolicyGroupIcon(policyGroup.value, CUSTOM_PROXY_GROUP_ICON)
    ensureCustomPolicyGroupIcon(directPolicyGroup.value, CUSTOM_DIRECT_PROXY_GROUP_ICON)
    showNotification({
      content: `已保存策略名称：${policyGroup.value} / ${directPolicyGroup.value}`,
      type: 'alert-success',
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

const confirmApplyToYaml = async () => {
  if (!customRules.value?.ruleUrl) return

  submitting.value = true

  try {
    const result = await applyCustomRuleToActiveYamlAPI(customRules.value.ruleUrl)
    applyDialogVisible.value = false
    ensureCustomPolicyGroupIcon(result.policyGroup || policyGroup.value, CUSTOM_PROXY_GROUP_ICON)
    ensureCustomPolicyGroupIcon(
      result.directPolicyGroup || directPolicyGroup.value,
      CUSTOM_DIRECT_PROXY_GROUP_ICON,
    )

    if (
      (result.policyGroup && result.policyGroup !== policyGroup.value) ||
      (result.directPolicyGroup && result.directPolicyGroup !== directPolicyGroup.value)
    ) {
      await updateCustomRulesSettingsAPI({
        policyGroup: result.policyGroup || policyGroup.value,
        directPolicyGroup: result.directPolicyGroup || directPolicyGroup.value,
      })
      policyGroup.value = result.policyGroup || policyGroup.value
      directPolicyGroup.value = result.directPolicyGroup || directPolicyGroup.value
      await loadCustomRules()
    }

    showNotification({
      content: result.changed
        ? `已写入当前 YAML：${result.configPath}，备份：${result.backupPath}，正在重新加载配置...`
        : `当前 YAML 已经包含自定义规则：${result.configPath}，正在重新加载配置...`,
      type: result.changed ? 'alert-success' : 'alert-info',
      timeout: 6000,
    })

    await reloadConfigsAPI().catch(() => null)
    const refreshed = await refreshRuntimeRulesAndProxies()

    showNotification({
      content: refreshed
        ? '配置已重新加载，策略组和规则列表已刷新'
        : '已写入 YAML，但当前控制器暂未刷新成功，请稍后手动刷新页面',
      type: refreshed ? 'alert-success' : 'alert-warning',
      timeout: refreshed ? 3600 : 8000,
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
