import { ROUTE_NAME } from '@/constant'
import { showNotification } from '@/helper/notification'
import { getUrlFromBackend, shouldUseServerProxy } from '@/helper/utils'
import router from '@/router'
import {
  ACCESS_PASSWORD_REQUIRED_CODE,
  fetchServerApi,
  markServerAuthenticationRequired,
} from '@/store/auth'
import { autoUpgradeCore, checkUpgradeCore } from '@/store/settings'
import { activeBackend, activeUuid } from '@/store/setup'
import type {
  Backend,
  Config,
  DNSQuery,
  NodeRank,
  Proxy,
  ProxyProvider,
  Rule,
  RuleProvider,
} from '@/types'
import axios, { AxiosError } from 'axios'
import { debounce } from 'lodash'
import ReconnectingWebSocket from 'reconnectingwebsocket'
import { computed, nextTick, ref, watch } from 'vue'

declare module 'axios' {
  export interface AxiosRequestConfig {
    skipErrorNotification?: boolean
  }
}

axios.interceptors.request.use((config) => {
  if (shouldUseServerProxy(activeBackend.value)) {
    config.baseURL = '/api/controller'
    config.headers['x-zashboard-target-base'] = getUrlFromBackend(activeBackend.value!)
    config.headers['x-zashboard-target-secret'] = activeBackend.value?.password || ''
    delete config.headers['Authorization']
  } else {
    config.baseURL = getUrlFromBackend(activeBackend.value!)
    config.headers['Authorization'] = 'Bearer ' + activeBackend.value?.password
  }
  return config
})

const ignoreNotificationUrls = ['/delay', '/weights']

axios.interceptors.response.use(
  null,
  (
    error: AxiosError<{
      code?: string
      message: string
    }>,
  ) => {
    const responseStatus = error.response?.status ?? error.status
    const responseCode = error.response?.data?.code

    if (responseStatus === 401 && responseCode === ACCESS_PASSWORD_REQUIRED_CODE) {
      markServerAuthenticationRequired()
      return Promise.reject(error)
    }

    if (responseStatus === 401 && activeUuid.value) {
      const currentBackendUuid = activeUuid.value
      activeUuid.value = null
      router.push({
        name: ROUTE_NAME.setup,
        query: { editBackend: currentBackendUuid },
      })
      nextTick(() => {
        showNotification({ content: 'unauthorizedTip' })
      })
    } else if (
      !error.config?.skipErrorNotification &&
      !ignoreNotificationUrls.some((url) => error.config?.url?.endsWith(url))
    ) {
      const errorMessage = error.response?.data?.message || error.message

      showNotification({
        key: errorMessage,
        content: `${error.config?.url} \n${errorMessage}`,
        type: 'alert-error',
      })
      return Promise.reject(error)
    }

    return error
  },
)

export const version = ref()
export const isCoreUpdateAvailable = ref(false)
export const fetchVersionAPI = () => {
  return axios.get<{ version: string }>('/version')
}
export const isSingBox = computed(() => version.value?.includes('sing-box'))
export const zashboardVersion = ref(__APP_VERSION__)
const UI_RELEASES_API = 'https://api.github.com/repos/520pt/Lufei-ClashBoard/releases/latest'

watch(
  activeBackend,
  async (val) => {
    if (val) {
      const { data } = await fetchVersionAPI()

      version.value = data?.version || ''
      if (isSingBox.value || !checkUpgradeCore.value || activeBackend.value?.disableUpgradeCore)
        return
      isCoreUpdateAvailable.value = await fetchBackendUpdateAvailableAPI()

      if (isCoreUpdateAvailable.value && autoUpgradeCore.value) {
        upgradeCoreAPI('auto')
      }
    }
  },
  { immediate: true },
)

export const fetchProxiesAPI = () => {
  return axios.get<{ proxies: Record<string, Proxy> }>('/proxies')
}

export const selectProxyAPI = (proxyGroup: string, name: string) => {
  return axios.put(`/proxies/${encodeURIComponent(proxyGroup)}`, { name })
}

export const deleteFixedProxyAPI = (proxyGroup: string) => {
  return axios.delete(`/proxies/${encodeURIComponent(proxyGroup)}`)
}

export const fetchProxyLatencyAPI = (proxyName: string, url: string, timeout: number) => {
  return axios.get<{ delay: number }>(`/proxies/${encodeURIComponent(proxyName)}/delay`, {
    params: {
      url,
      timeout,
    },
  })
}

export const fetchProxyGroupLatencyAPI = (proxyName: string, url: string, timeout: number) => {
  return axios.get<Record<string, number>>(`/group/${encodeURIComponent(proxyName)}/delay`, {
    params: {
      url,
      timeout,
    },
  })
}

export const fetchSmartWeightsAPI = () => {
  return axios.get<{
    message: string
    weights: Record<string, NodeRank[]>
  }>(`/group/weights`)
}

// deprecated
export const fetchSmartGroupWeightsAPI = (proxyName: string) => {
  return axios.get<{
    message: string
    weights: NodeRank[]
  }>(`/group/${encodeURIComponent(proxyName)}/weights`)
}

export const flushSmartGroupWeightsAPI = () => {
  return axios.post(`/cache/smart/flush`)
}

export const fetchProxyProviderAPI = (options: { skipErrorNotification?: boolean } = {}) => {
  return axios.get<{ providers: Record<string, ProxyProvider> }>('/providers/proxies', {
    skipErrorNotification: options.skipErrorNotification,
  })
}

export const updateProxyProviderAPI = (name: string) => {
  return axios.put(`/providers/proxies/${encodeURIComponent(name)}`)
}

export const proxyProviderHealthCheckAPI = (name: string) => {
  return axios.get<Record<string, number>>(
    `/providers/proxies/${encodeURIComponent(name)}/healthcheck`,
    {
      timeout: 15000,
    },
  )
}

export const fetchRulesAPI = () => {
  return axios.get<{ rules: Rule[] }>('/rules')
}

export const toggleRuleDisabledAPI = (data: Record<number, boolean>) => {
  return axios.patch(`/rules/disable`, data)
}

export const toggleRuleDisabledSingBoxAPI = (uuid: string) => {
  return axios.put(`/rules/${encodeURIComponent(uuid)}`)
}

export const fetchRuleProvidersAPI = () => {
  return axios.get<{ providers: Record<string, RuleProvider> }>('/providers/rules')
}

export const updateRuleProviderAPI = (
  name: string,
  options: { skipErrorNotification?: boolean } = {},
) => {
  return axios.put(`/providers/rules/${encodeURIComponent(name)}`, undefined, {
    skipErrorNotification: options.skipErrorNotification,
  })
}

export const blockConnectionByIdAPI = (id: string) => {
  return axios.delete(`/connections/smart/${id}`)
}

export const disconnectByIdAPI = (id: string) => {
  return axios.delete(`/connections/${id}`)
}

export const disconnectAllAPI = () => {
  return axios.delete('/connections')
}

export const getConfigsAPI = () => {
  return axios.get<Config>('/configs')
}

export const patchConfigsAPI = (configs: Record<string, string | boolean | object | number>) => {
  return axios.patch('/configs', configs)
}

export const flushFakeIPAPI = () => {
  return axios.post('/cache/fakeip/flush')
}

export const flushDNSCacheAPI = () => {
  return axios.post('/cache/dns/flush')
}

export const reloadConfigsAPI = (options: { skipErrorNotification?: boolean } = {}) => {
  return axios.put(
    '/configs?reload=true',
    { path: '', payload: '' },
    { skipErrorNotification: options.skipErrorNotification },
  )
}

export const upgradeUIAPI = () => {
  return axios.post('/upgrade/ui')
}

export const updateGeoDataAPI = () => {
  return axios.post('/configs/geo')
}

export const upgradeCoreAPI = (type: 'release' | 'alpha' | 'auto') => {
  const url = type === 'auto' ? '/upgrade' : `/upgrade?channel=${type}`

  return axios.post(url)
}

export const restartCoreAPI = (options: { skipErrorNotification?: boolean } = {}) => {
  return axios.post('/restart', undefined, {
    skipErrorNotification: options.skipErrorNotification,
  })
}

export const queryDNSAPI = (params: { name: string; type: string }) => {
  return axios.get<DNSQuery>('/dns/query', {
    params,
  })
}

const createWebSocket = <T>(url: string, searchParams?: Record<string, string>) => {
  const backend = activeBackend.value!
  const currentOrigin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost'
  const resurl = new URL(`/api/controller-ws/${url}`, currentOrigin)

  resurl.protocol = resurl.protocol === 'https:' ? 'wss:' : 'ws:'
  resurl.searchParams.append('targetBase', getUrlFromBackend(backend))

  if (backend?.password) {
    resurl.searchParams.append('secret', backend.password)
  }

  if (searchParams) {
    Object.entries(searchParams).forEach(([key, value]) => {
      resurl.searchParams.append(key, value)
    })
  }

  const data = ref<T>()
  const websocket = new ReconnectingWebSocket(resurl.toString())

  const close = () => {
    websocket.close()
  }

  const messageHandler = ({ data: message }: { data: string }) => {
    data.value = JSON.parse(message)
  }

  websocket.onmessage = url === 'logs' ? messageHandler : debounce(messageHandler, 100)

  return {
    data,
    close,
  }
}

export const fetchConnectionsAPI = <T>() => {
  return createWebSocket<T>('connections')
}

export const fetchLogsAPI = <T>(params: Record<string, string> = {}) => {
  return createWebSocket<T>('logs', params)
}

export const fetchMemoryAPI = <T>() => {
  return createWebSocket<T>('memory')
}

export const fetchTrafficAPI = <T>() => {
  return createWebSocket<T>('traffic')
}

export const isBackendAvailable = async (backend: Backend, timeout: number = 10000) => {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeout)

  try {
    const headers: Record<string, string> = {}
    let url = `${getUrlFromBackend(backend)}/version`

    if (shouldUseServerProxy(backend)) {
      url = '/api/controller/version'
      headers['x-zashboard-target-base'] = getUrlFromBackend(backend)
      headers['x-zashboard-target-secret'] = backend.password || ''
    } else {
      headers['Authorization'] = `Bearer ${backend.password}`
    }

    const res = await fetchServerApi(url, {
      method: 'GET',
      headers,
      signal: controller.signal,
    })

    return res.ok
  } catch {
    return false
  } finally {
    clearTimeout(timeoutId)
  }
}

const CACHE_DURATION = 1000 * 60 * 60

interface CacheEntry<T> {
  timestamp: number
  version: string
  data: T
}

const normalizeVersionLabel = (version: string) => {
  return version.trim().replace(/^v/i, '')
}

const parseVersionParts = (version: string) => {
  return normalizeVersionLabel(version)
    .split('.')
    .map((part) => {
      const match = /^(\d+)/.exec(part.trim())

      return match ? Number.parseInt(match[1], 10) : 0
    })
}

const compareDisplayVersions = (currentVersion: string, nextVersion: string) => {
  const current = parseVersionParts(currentVersion)
  const next = parseVersionParts(nextVersion)
  const length = Math.max(current.length, next.length)

  for (let index = 0; index < length; index++) {
    const currentPart = current[index] ?? 0
    const nextPart = next[index] ?? 0

    if (nextPart !== currentPart) {
      return nextPart - currentPart
    }
  }

  return 0
}

export const getDisplayAppVersion = (versionText: string) => {
  return normalizeVersionLabel(versionText)
}

async function fetchWithLocalCache<T>(url: string, version: string): Promise<T> {
  const cacheKey = 'cache/' + url
  const cacheRaw = localStorage.getItem(cacheKey)

  if (cacheRaw) {
    try {
      const cache: CacheEntry<T> = JSON.parse(cacheRaw)
      const now = Date.now()

      if (now - cache.timestamp < CACHE_DURATION && cache.version === version) {
        return cache.data
      } else {
        localStorage.removeItem(cacheKey)
      }
    } catch (e) {
      console.warn('Failed to parse cache for', url, e)
    }
  }

  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Fetch failed: ${response.status} ${response.statusText}`)
  }

  const data: T = await response.json()
  const newCache: CacheEntry<T> = {
    timestamp: Date.now(),
    version,
    data,
  }

  localStorage.setItem(cacheKey, JSON.stringify(newCache))
  return data
}

export const fetchIsUIUpdateAvailable = async () => {
  try {
    const { tag_name } = await fetchWithLocalCache<{ tag_name: string }>(
      UI_RELEASES_API,
      zashboardVersion.value,
    )

    return Boolean(tag_name && compareDisplayVersions(zashboardVersion.value, tag_name) < 0)
  } catch (error) {
    if (error instanceof Error && error.message.includes('404')) {
      return false
    }

    throw error
  }
}

const check = async (url: string, versionNumber: string) => {
  const { assets } = await fetchWithLocalCache<{ assets: { name: string }[] }>(url, versionNumber)
  const alreadyLatest = assets.some(({ name }) => name.includes(versionNumber))

  return !alreadyLatest
}

export const fetchBackendUpdateAvailableAPI = async () => {
  const match = /(alpha-smart|alpha|beta|meta)-?(\w+)/.exec(version.value)

  if (!match) {
    const { tag_name } = await fetchWithLocalCache<{ tag_name: string }>(
      'https://api.github.com/repos/MetaCubeX/mihomo/releases/latest',
      version.value,
    )

    return Boolean(tag_name && !tag_name.endsWith(version.value))
  }

  const channel = match[1],
    versionNumber = match[2]

  if (channel === 'meta')
    return await check(
      'https://api.github.com/repos/MetaCubeX/mihomo/releases/latest',
      versionNumber,
    )
  if (channel === 'alpha')
    return await check(
      'https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/Prerelease-Alpha',
      versionNumber,
    )
  if (channel === 'alpha-smart')
    return await check(
      'https://api.github.com/repos/vernesong/mihomo/releases/tags/Prerelease-Alpha',
      versionNumber,
    )

  return false
}

export type CustomRulePolicy = 'proxy' | 'direct'

export type CustomRuleEntry = {
  rule: string
  policy: CustomRulePolicy
}

export type CustomRulesSettings = {
  providerName: string
  directProviderName: string
  policyGroup: string
  directPolicyGroup: string
  fileName: string
  directFileName: string
}

export type CustomRulesPayload = {
  rules: CustomRuleEntry[]
  settings: CustomRulesSettings
  ruleUrl: string
  directRuleUrl: string
  snippets: {
    proxyGroupLine: string
    providerLine: string
    ruleLine: string
  }
}

export type ApplyCustomRuleYamlResult = {
  ok: boolean
  plugin: string
  configPath: string
  backupPath: string
  changed: boolean
  addedProvider: boolean
  updatedProvider?: boolean
  addedRule: boolean
  addedProxyGroup: boolean
  updatedProxyGroup?: boolean
  policyGroup?: string
  directPolicyGroup?: string
  removedConflictingProxyGroups?: number
  removedDuplicateProxyGroups?: number
  removedLegacyProxyGroups?: number
  removedLegacyRules?: number
  removedStaleProviderRules?: number
}

export const fetchCustomRulesAPI = async () => {
  const response = await fetchServerApi('/api/custom-rules', {
    headers: {
      Accept: 'application/json',
    },
    cache: 'no-store',
  })

  if (!response.ok) {
    throw new Error(`Failed to fetch custom rules: ${response.status}`)
  }

  return (await response.json()) as CustomRulesPayload
}

export const addCustomRuleAPI = async (
  target: string,
  kind = 'auto',
  policy: CustomRulePolicy = 'proxy',
) => {
  const response = await fetchServerApi('/api/custom-rules', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ target, kind, policy }),
  })

  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new Error(data?.message || `Failed to add custom rule: ${response.status}`)
  }

  return data as {
    rule?: string
    policy: CustomRulePolicy
    added?: boolean
    results?: Array<{
      target: string
      rule: string
      policy: CustomRulePolicy
      added: boolean
    }>
    errors?: Array<{
      target: string
      message: string
    }>
    addedCount?: number
    skippedCount?: number
    errorCount?: number
    rules: CustomRuleEntry[]
  }
}

export const deleteCustomRuleAPI = async (rule: string, policy: CustomRulePolicy = 'proxy') => {
  const response = await fetchServerApi('/api/custom-rules', {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ rule, policy }),
  })

  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new Error(data?.message || `Failed to delete custom rule: ${response.status}`)
  }

  return data as { removed: boolean; rules: CustomRuleEntry[] }
}

export const updateCustomRulesSettingsAPI = async (settings: Partial<CustomRulesSettings>) => {
  const response = await fetchServerApi('/api/custom-rules/settings', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(settings),
  })

  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new Error(data?.message || `Failed to update custom rules settings: ${response.status}`)
  }

  return data as { settings: CustomRulesSettings }
}

export const applyCustomRuleToActiveYamlAPI = async (ruleUrl: string) => {
  const response = await fetchServerApi('/api/openwrt-rule-source/apply-custom', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ ruleUrl }),
  })

  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new Error(data?.message || `Failed to apply custom rule YAML: ${response.status}`)
  }

  return data as ApplyCustomRuleYamlResult
}
