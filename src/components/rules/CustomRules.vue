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
              <div class="badge badge-ghost badge-sm">{{ totalEffectiveRuleCount }} 条有效规则</div>
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
            <div class="text-sm font-semibold">规则地址</div>
            <div
              class="bg-base-100 rounded-box border-base-300 flex min-w-0 items-center gap-2 border p-2"
            >
              <button
                class="min-w-0 flex-1 text-left font-mono text-xs break-all"
                type="button"
                @click="copyText(customRules?.ruleUrl || '')"
              >
                <span class="text-primary mr-2 font-sans font-semibold">代理</span
                >{{ customRules?.ruleUrl || '-' }}
              </button>
              <button
                class="btn btn-primary btn-xs shrink-0"
                type="button"
                :disabled="!customRules?.ruleUrl"
                @click="copyText(customRules?.ruleUrl || '')"
              >
                复制
              </button>
            </div>
            <div
              class="bg-base-100 rounded-box border-base-300 flex min-w-0 items-center gap-2 border p-2"
            >
              <button
                class="min-w-0 flex-1 text-left font-mono text-xs break-all"
                type="button"
                @click="copyText(customRules?.directRuleUrl || '')"
              >
                <span class="text-success mr-2 font-sans font-semibold">直连</span
                >{{ customRules?.directRuleUrl || '-' }}
              </button>
              <button
                class="btn btn-success btn-xs shrink-0"
                type="button"
                :disabled="!customRules?.directRuleUrl"
                @click="copyText(customRules?.directRuleUrl || '')"
              >
                复制
              </button>
            </div>
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
            支持批量粘贴域名、IP、URL 或 DOMAIN-KEYWORD,m-team 这类 Clash 规则。
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
          <textarea
            v-model.trim="target"
            class="textarea textarea-bordered textarea-sm join-item min-h-20 min-w-0 flex-1 leading-5"
            placeholder="输入域名、网址、IP、CIDR 或多行 Clash 规则"
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
            代理 {{ proxyRuleCount }} 条，直连 {{ directRuleCount }} 条；可以用 <code># PT</code>
            这类注释做分组标记。
          </div>
        </div>
      </div>

      <div class="grid gap-3 xl:grid-cols-2">
        <div class="bg-base-200 rounded-box border-base-300 min-w-0 border">
          <div class="border-base-300 flex items-center justify-between gap-3 border-b px-3 py-2">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="badge badge-primary badge-sm">代理</span>
                <span class="font-semibold">ziyong.list</span>
              </div>
              <div class="text-base-content/60 mt-1 text-xs">
                {{ proxyRuleCount }} 条有效规则，注释行会原样保留。
              </div>
            </div>
            <button
              class="btn btn-primary btn-sm shrink-0"
              type="button"
              :disabled="submitting"
              @click="handleSaveRulesText('proxy')"
            >
              保存
            </button>
          </div>
          <div class="border-base-300 flex flex-col gap-2 border-b p-3">
            <div class="flex flex-col gap-2 md:flex-row md:items-center">
              <input
                v-model.trim="newProxyGroupName"
                class="input input-bordered input-sm min-w-0 flex-1"
                placeholder="输入分组名，例如 PT"
              />
              <button
                class="btn btn-primary btn-sm"
                type="button"
                @click="insertGroupHeading('proxy')"
              >
                新增分组
              </button>
            </div>
            <div class="flex flex-wrap gap-2">
              <button
                v-for="group in proxyRuleGroups"
                :key="`proxy-${group.name}`"
                class="badge badge-outline gap-1 py-3"
                type="button"
                @click="newProxyGroupName = group.name"
              >
                # {{ group.name }}
                <span class="text-base-content/50">{{ group.ruleCount }} 条</span>
              </button>
            </div>
          </div>
          <textarea
            v-model="proxyRulesText"
            class="textarea custom-rule-editor bg-base-100 min-h-[28rem] w-full resize-y rounded-t-none border-0 font-mono text-xs leading-6 focus:outline-none"
            spellcheck="false"
            placeholder="# PT
DOMAIN-KEYWORD,m-team
DOMAIN-SUFFIX,cnboy.org"
          />
        </div>

        <div class="bg-base-200 rounded-box border-base-300 min-w-0 border">
          <div class="border-base-300 flex items-center justify-between gap-3 border-b px-3 py-2">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="badge badge-success badge-sm">直连</span>
                <span class="font-semibold">ziyong-direct.list</span>
              </div>
              <div class="text-base-content/60 mt-1 text-xs">
                {{ directRuleCount }} 条有效规则，适合放国内站点或需要直连的 IP。
              </div>
            </div>
            <button
              class="btn btn-success btn-sm shrink-0"
              type="button"
              :disabled="submitting"
              @click="handleSaveRulesText('direct')"
            >
              保存
            </button>
          </div>
          <div class="border-base-300 flex flex-col gap-2 border-b p-3">
            <div class="flex flex-col gap-2 md:flex-row md:items-center">
              <input
                v-model.trim="newDirectGroupName"
                class="input input-bordered input-sm min-w-0 flex-1"
                placeholder="输入分组名，例如 国内直连"
              />
              <button
                class="btn btn-success btn-sm"
                type="button"
                @click="insertGroupHeading('direct')"
              >
                新增分组
              </button>
            </div>
            <div class="flex flex-wrap gap-2">
              <button
                v-for="group in directRuleGroups"
                :key="`direct-${group.name}`"
                class="badge badge-outline gap-1 py-3"
                type="button"
                @click="newDirectGroupName = group.name"
              >
                # {{ group.name }}
                <span class="text-base-content/50">{{ group.ruleCount }} 条</span>
              </button>
            </div>
          </div>
          <textarea
            v-model="directRulesText"
            class="textarea custom-rule-editor bg-base-100 min-h-[28rem] w-full resize-y rounded-t-none border-0 font-mono text-xs leading-6 focus:outline-none"
            spellcheck="false"
            placeholder="# 国内直连
DOMAIN-SUFFIX,example.cn
IP-CIDR,10.0.0.0/8,no-resolve"
          />
        </div>
      </div>
    </div>

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
  fetchCustomRulesAPI,
  reloadConfigsAPI,
  restartCoreAPI,
  updateCustomRulesSettingsAPI,
  updateCustomRulesTextAPI,
  updateRuleProviderAPI,
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
import { fetchRules, ruleProviderList, rules } from '@/store/rules'
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
const applyDialogVisible = ref(false)
const proxyRulesText = ref('')
const directRulesText = ref('')
const newProxyGroupName = ref('')
const newDirectGroupName = ref('')

const isCustomRuleComment = (value: string) => value.trim().startsWith('#')

const normalizeCustomGroupName = (value: string) => value.replace(/^#+\s*/, '').trim() || '未分组'

const getRulesText = (policy: CustomRulePolicy) => {
  return (
    customRules.value?.rules
      .filter((entry) => entry.policy === policy)
      .map((entry) => entry.rule)
      .join('\n') || ''
  )
}

const countEffectiveRules = (text: string) => {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !isCustomRuleComment(line)).length
}

const countEffectiveRuleEntries = (policy: CustomRulePolicy) => {
  return (
    customRules.value?.rules.filter(
      (entry) => entry.policy === policy && !isCustomRuleComment(entry.rule),
    ).length || 0
  )
}

const parseRuleGroupsFromText = (text: string, policy: CustomRulePolicy) => {
  const groups: Array<{ name: string; policy: CustomRulePolicy; ruleCount: number }> = []
  let currentGroup: { name: string; policy: CustomRulePolicy; ruleCount: number } | null = null

  const ensureGroup = (name: string) => {
    const groupName = normalizeCustomGroupName(name)

    if (currentGroup?.name === groupName) {
      return currentGroup
    }

    currentGroup = {
      name: groupName,
      policy,
      ruleCount: 0,
    }
    groups.push(currentGroup)

    return currentGroup
  }

  text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .forEach((line) => {
      if (isCustomRuleComment(line)) {
        ensureGroup(line)
        return
      }

      ensureGroup(currentGroup?.name || '未分组').ruleCount += 1
    })

  return groups
}

const proxyRuleCount = computed(() => countEffectiveRules(proxyRulesText.value))
const directRuleCount = computed(() => countEffectiveRules(directRulesText.value))
const totalEffectiveRuleCount = computed(
  () => countEffectiveRuleEntries('proxy') + countEffectiveRuleEntries('direct'),
)
const proxyRuleGroups = computed(() => parseRuleGroupsFromText(proxyRulesText.value, 'proxy'))
const directRuleGroups = computed(() => parseRuleGroupsFromText(directRulesText.value, 'direct'))

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
    proxyRulesText.value = getRulesText('proxy')
    directRulesText.value = getRulesText('direct')
    ensureCustomPolicyGroupIcon(policyGroup.value, CUSTOM_PROXY_GROUP_ICON)
    ensureCustomPolicyGroupIcon(directPolicyGroup.value, CUSTOM_DIRECT_PROXY_GROUP_ICON)
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : String(error)
  } finally {
    loading.value = false
  }
}

const appendLine = (text: string, line: string) => {
  const normalizedText = text.trimEnd()

  return `${normalizedText}${normalizedText ? '\n' : ''}${line}\n`
}

const insertGroupHeading = (policy: CustomRulePolicy) => {
  const groupName =
    policy === 'direct' ? newDirectGroupName.value.trim() : newProxyGroupName.value.trim()

  if (!groupName) {
    showNotification({ content: '请输入分组名', type: 'alert-warning' })
    return
  }

  if (policy === 'direct') {
    directRulesText.value = appendLine(directRulesText.value, `# ${groupName}`)
    newDirectGroupName.value = ''
    return
  }

  proxyRulesText.value = appendLine(proxyRulesText.value, `# ${groupName}`)
  newProxyGroupName.value = ''
}

const copyText = async (value: string) => {
  if (!value) return

  try {
    await navigator.clipboard.writeText(value)
    showNotification({ content: '已复制到剪切板', type: 'alert-success', timeout: 1800 })
    return
  } catch (error) {
    console.warn('Failed to copy custom rule text with navigator.clipboard, falling back', error)
  }

  const textArea = document.createElement('textarea')
  textArea.value = value
  textArea.setAttribute('readonly', 'readonly')
  textArea.style.position = 'fixed'
  textArea.style.opacity = '0'
  document.body.appendChild(textArea)
  textArea.select()

  try {
    document.execCommand('copy')
    showNotification({ content: '已复制到剪切板', type: 'alert-success', timeout: 1800 })
  } catch (fallbackError) {
    console.warn('Failed to copy custom rule text with fallback', fallbackError)
    showNotification({
      content: '复制失败，请手动选择文本复制',
      type: 'alert-error',
      timeout: 2400,
    })
  } finally {
    document.body.removeChild(textArea)
  }
}

const sleep = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms))

const getPolicyLabel = (policy: CustomRulePolicy) => (policy === 'direct' ? '直连' : '代理')

type CustomRuleRefreshResult = 'updated' | 'restarted' | 'failed'

const getRefreshStatusText = (status: CustomRuleRefreshResult) => {
  if (status === 'updated') return '，规则源已刷新'
  if (status === 'restarted') return '，核心已重启并刷新'
  return ''
}

const isRuntimeRuleSetType = (type: string) => {
  return type.toLowerCase().replace(/[-_\s]/g, '') === 'ruleset'
}

const isCustomRuntimeReady = (requireRuleCounts = true) => {
  const providerName = customRules.value?.settings.providerName || ''
  const directProviderName = customRules.value?.settings.directProviderName || ''
  const currentPolicyGroup = policyGroup.value
  const currentDirectPolicyGroup = directPolicyGroup.value
  const proxyRuleCount = countEffectiveRuleEntries('proxy')
  const directRuleCount = countEffectiveRuleEntries('direct')

  if (!providerName || !directProviderName || !currentPolicyGroup || !currentDirectPolicyGroup) {
    return false
  }

  const provider = ruleProviderList.value.find((item) => item.name === providerName)
  const directProvider = ruleProviderList.value.find((item) => item.name === directProviderName)

  if (!provider || !directProvider) {
    return false
  }

  const hasExpectedRuleCounts =
    provider.ruleCount === proxyRuleCount && directProvider.ruleCount === directRuleCount
  const hasRules =
    rules.value.some(
      (rule) =>
        isRuntimeRuleSetType(rule.type) &&
        rule.payload === providerName &&
        rule.proxy === currentPolicyGroup,
    ) &&
    rules.value.some(
      (rule) =>
        isRuntimeRuleSetType(rule.type) &&
        rule.payload === directProviderName &&
        rule.proxy === currentDirectPolicyGroup,
    )

  return hasRules && (!requireRuleCounts || hasExpectedRuleCounts)
}

const silentRefreshRuntimeState = () =>
  Promise.allSettled([
    fetchProxies({ skipErrorNotification: true }),
    fetchRules({ skipErrorNotification: true }),
  ])

const refreshRuntimeRulesAndProxies = async () => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const results = await silentRefreshRuntimeState()

    if (results.every((result) => result.status === 'fulfilled')) {
      return true
    }

    await sleep(3000)
  }

  return false
}

const waitForCustomRuntimeReady = async (attempts = 18, delay = 2500, requireRuleCounts = true) => {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    await silentRefreshRuntimeState()

    if (isCustomRuntimeReady(requireRuleCounts)) {
      return true
    }

    await sleep(delay)
  }

  return false
}

const refreshAllCustomRuleProviders = async () => {
  const providerNames = [
    customRules.value?.settings.providerName,
    customRules.value?.settings.directProviderName,
  ].filter((name): name is string => Boolean(name))

  if (providerNames.length !== 2) {
    return false
  }

  await Promise.allSettled(
    providerNames.map((providerName) =>
      updateRuleProviderAPI(providerName, { skipErrorNotification: true }),
    ),
  )

  return await waitForCustomRuntimeReady(10, 1500)
}

const restartCoreAndVerifyCustomRules = async () => {
  let activateError = ''

  try {
    await reloadConfigsAPI({ skipErrorNotification: true })
  } catch (error) {
    activateError = error instanceof Error ? error.message : String(error)
  }

  if (
    (await waitForCustomRuntimeReady(18, 2500, false)) &&
    (await refreshAllCustomRuleProviders())
  ) {
    return true
  }

  try {
    await restartCoreAPI({ skipErrorNotification: true })
  } catch (error) {
    activateError = activateError || (error instanceof Error ? error.message : String(error))
  }

  if (
    (await waitForCustomRuntimeReady(18, 2500, false)) &&
    (await refreshAllCustomRuleProviders())
  ) {
    return true
  }

  throw new Error(
    `配置重载/核心重启后仍未检测到自定义规则集，请检查 OpenClash 是否已加载当前 YAML，以及规则地址是否可访问${
      activateError ? `。底层错误：${activateError}` : ''
    }`,
  )
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

const refreshCustomRuleProvider = async (
  policy: CustomRulePolicy,
): Promise<CustomRuleRefreshResult> => {
  const providerName =
    policy === 'direct'
      ? customRules.value?.settings.directProviderName
      : customRules.value?.settings.providerName

  if (!providerName) return 'failed'

  try {
    await updateRuleProviderAPI(providerName, { skipErrorNotification: true })

    if (await waitForCustomRuntimeReady(5, 1000)) {
      return 'updated'
    }

    throw new Error('规则源刷新接口已返回，但运行时规则数量尚未更新')
  } catch (error) {
    showNotification({
      content: `规则已保存，但${getPolicyLabel(policy)}规则源刷新失败，正在尝试重启核心让规则生效...`,
      type: 'alert-warning',
      timeout: 4200,
    })

    try {
      await restartCoreAndVerifyCustomRules()
      return 'restarted'
    } catch (restartError) {
      showNotification({
        content: `规则已保存，但${getPolicyLabel(policy)}规则源暂未确认生效。请先点击“一键写入当前 YAML”并等待核心重启；如果已经写入，请确认 YAML 里的规则地址是 OpenWrt 可访问的 NAS/局域网 IP。详情：${
          restartError instanceof Error
            ? restartError.message
            : error instanceof Error
              ? error.message
              : String(error)
        }`,
        type: 'alert-warning',
        timeout: 10000,
      })
    }

    return 'failed'
  }
}

const handleAddRule = async () => {
  submitting.value = true

  try {
    const selectedPolicy = targetPolicy.value
    const result = await addCustomRuleAPI(target.value, kind.value, selectedPolicy)
    target.value = ''
    await loadCustomRules()
    const refreshStatus = await refreshCustomRuleProvider(selectedPolicy)
    const isBatchResult = Array.isArray(result.results)
    const firstResult = result.results?.[0]
    const addedCount = result.addedCount ?? (result.added ? 1 : 0)
    const skippedCount = result.skippedCount ?? (result.added === false ? 1 : 0)
    const conflictCount =
      result.conflictCount ?? result.results?.filter((item) => item.conflict).length ?? 0
    const errorCount = result.errorCount ?? 0
    const batchSummary = isBatchResult
      ? `新增 ${addedCount} 条，已存在 ${skippedCount} 条${
          conflictCount ? `，冲突 ${conflictCount} 条` : ''
        }${errorCount ? `，失败 ${errorCount} 条` : ''}`
      : firstResult?.conflict
        ? `规则冲突：${firstResult.rule || ''} 已在 ${firstResult.conflictSource || '其他自定义规则'} 中存在`
        : result.added
          ? `已添加到${getPolicyLabel(selectedPolicy)}：${result.rule || firstResult?.rule || ''}`
          : `${getPolicyLabel(selectedPolicy)}已存在：${result.rule || firstResult?.rule || ''}`

    showNotification({
      content: `${batchSummary}${getRefreshStatusText(refreshStatus)}`,
      type: addedCount > 0 ? 'alert-success' : 'alert-info',
      timeout: refreshStatus === 'failed' ? 3200 : 2400,
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

const handleSaveRulesText = async (policy: CustomRulePolicy) => {
  submitting.value = true

  try {
    const text = policy === 'direct' ? directRulesText.value : proxyRulesText.value
    const result = await updateCustomRulesTextAPI(policy, text)
    await loadCustomRules()
    const refreshStatus = await refreshCustomRuleProvider(policy)

    showNotification({
      content: `已保存${getPolicyLabel(policy)}规则：${result.updatedCount} 条有效规则，${result.commentCount} 条分组注释${getRefreshStatusText(refreshStatus)}`,
      type: 'alert-success',
      timeout: refreshStatus === 'failed' ? 3600 : 2400,
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
        ? `已更新 YAML：${result.configPath}${
            result.runtimeChanged && result.runtimeConfigPath
              ? `，并同步运行配置：${result.runtimeConfigPath}`
              : ''
          }${result.backupPath ? `，备份：${result.backupPath}` : ''}，正在重载配置...`
        : `当前 YAML 已经包含自定义规则：${result.configPath}，正在重载配置...`,
      type: result.changed ? 'alert-success' : 'alert-info',
      timeout: 6000,
    })

    await restartCoreAndVerifyCustomRules()
    const refreshed = await refreshRuntimeRulesAndProxies()

    showNotification({
      content: refreshed
        ? '配置已重载，并已确认自定义规则集加载成功'
        : '配置已重载并确认自定义规则集加载成功，但列表刷新暂未完成，请稍后手动刷新页面',
      type: refreshed ? 'alert-success' : 'alert-warning',
      timeout: refreshed ? 4200 : 8000,
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

<style scoped>
.custom-rule-editor {
  tab-size: 2;
  white-space: pre;
}
</style>
