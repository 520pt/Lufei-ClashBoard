import { showNotification } from '@/helper/notification'
import {
  applyManagedStorageSnapshot,
  getManagedStorageSnapshot,
  normalizeManagedStorageSnapshot,
  persistManagedStorageSnapshot,
  stabilizeManagedStorageSnapshot,
} from '@/helper/persistentStorage'
import { useStorage } from '@vueuse/core'
const IMPORT_SETTINGS_URL_KEY = 'config/import-settings-url'
const LUFEI_SELF_USE_SETTINGS_ENABLED_KEY = 'config/lufei-self-use-settings-enabled'
const LUFEI_SELF_USE_SETTINGS_HASH_KEY = 'cache/lufei-self-use-settings-hash'
export const CUSTOM_PROXY_GROUP_ICON_NAME = '自定义'
export const CUSTOM_PROXY_GROUP_ICON_UUID = '8f949d69-cd69-4773-b62f-61aeb5150cf2'
export const CUSTOM_PROXY_GROUP_ICON =
  'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0ODAiIGhlaWdodD0iNDgwIiB2aWV3Qm94PSIwIDAgMjQgMjQiPgoJPHBhdGggZmlsbD0iIzY0OTM0OCIgZD0iTTIwLjU2MiAxMC4xODhjLjI1LS42ODguMzEzLTEuMzc2LjI1LTIuMDYzYy0uMDYyLS42ODctLjMxMi0xLjM3NS0uNjI1LTJjLS41NjItLjkzNy0xLjM3NS0xLjY4Ny0yLjMxMi0yLjEyNWMtMS0uNDM3LTIuMDYzLS41NjItMy4xMjUtLjMxMmMtLjUtLjUtMS4wNjMtLjkzOC0xLjY4OC0xLjI1UzExLjY4NyAyIDExIDJhNS4xNyA1LjE3IDAgMCAwLTMgLjkzOGMtLjg3NS42MjQtMS41IDEuNS0xLjgxMyAyLjVjLS43NS4xODctMS4zNzUuNS0yIC44NzVjLS41NjIuNDM3LTEgMS0xLjM3NSAxLjU2MmMtLjU2Mi45MzgtLjc1IDItLjYyNSAzLjA2M2E1LjQ0IDUuNDQgMCAwIDAgMS4yNSAyLjg3NGE0LjcgNC43IDAgMCAwLS4yNSAyLjA2M2MuMDYzLjY4OC4zMTMgMS4zNzUuNjI1IDJjLjU2My45MzggMS4zNzUgMS42ODggMi4zMTMgMi4xMjVjMSAuNDM4IDIuMDYyLjU2MyAzLjEyNS4zMTNjLjUuNSAxLjA2Mi45MzcgMS42ODcgMS4yNVMxMi4zMTIgMjIgMTMgMjJhNS4xNyA1LjE3IDAgMCAwIDMtLjkzN2MuODc1LS42MjUgMS41LTEuNSAxLjgxMi0yLjVhNC41NCA0LjU0IDAgMCAwIDEuOTM4LS44NzVjLjU2Mi0uNDM4IDEuMDYyLS45MzggMS4zNzUtMS41NjNjLjU2Mi0uOTM3Ljc1LTIgLjYyNS0zLjA2MmMtLjEyNS0xLjA2My0uNS0yLjA2My0xLjE4OC0yLjg3Nm0tNy41IDEwLjVjLTEgMC0xLjc1LS4zMTMtMi40MzctLjg3NWMwIDAgLjA2Mi0uMDYzLjEyNS0uMDYzbDQtMi4zMTJhLjUuNSAwIDAgMCAuMjUtLjI1YS41Ny41NyAwIDAgMCAuMDYyLS4zMTNWMTEuMjVsMS42ODggMXY0LjYyNWEzLjY4NSAzLjY4NSAwIDAgMS0zLjY4OCAzLjgxM001IDE3LjI1Yy0uNDM4LS43NS0uNjI1LTEuNjI1LS40MzgtMi41YzAgMCAuMDYzLjA2My4xMjUuMDYzbDQgMi4zMTJhLjU2LjU2IDAgMCAwIC4zMTMuMDYzYy4xMjUgMCAuMjUgMCAuMzEyLS4wNjNsNC44NzUtMi44MTJ2MS45MzdsLTQuMDYyIDIuMzc1QTMuNyAzLjcgMCAwIDEgNy4zMTIgMTljLTEtLjI1LTEuODEyLS44NzUtMi4zMTItMS43NU0zLjkzNyA4LjU2M2EzLjggMy44IDAgMCAxIDEuOTM4LTEuNjI2djQuNzUxYzAgLjEyNCAwIC4yNS4wNjIuMzEyYS41LjUgMCAwIDAgLjI1LjI1bDQuODc1IDIuODEzbC0xLjY4NyAxbC00LTIuMzEzYTMuNyAzLjcgMCAwIDEtMS43NS0yLjI1Yy0uMjUtLjkzNy0uMTg4LTIuMDYyLjMxMi0yLjkzN00xNy43NSAxMS43NWwtNC44NzUtMi44MTJsMS42ODctMWw0IDIuMzEyYy42MjUuMzc1IDEuMTI1Ljg3NSAxLjQzOCAxLjVzLjUgMS4zMTMuNDM3IDIuMDYzYTMuNyAzLjcgMCAwIDEtLjc1IDEuOTM3Yy0uNDM3LjU2My0xIDEtMS42ODcgMS4yNXYtNC43NWMwLS4xMjUgMC0uMjUtLjA2My0uMzEyYzAgMC0uMDYyLS4xMjYtLjE4Ny0uMTg4bTEuNjg3LTIuNXMtLjA2Mi0uMDYyLS4xMjUtLjA2MmwtNC0yLjMxM2MtLjEyNS0uMDYyLS4xODctLjA2Mi0uMzEyLS4wNjJzLS4yNSAwLS4zMTMuMDYyTDkuODEyIDkuNjg4VjcuNzVsNC4wNjMtMi4zNzVjLjYyNS0uMzc1IDEuMzEyLS41IDIuMDYyLS41Yy42ODggMCAxLjM3NS4yNSAyIC42ODhjLjU2My40MzcgMS4wNjMgMSAxLjMxMyAxLjYyNXMuMzEyIDEuMzc1LjE4NyAyLjA2Mm0tMTAuNSAzLjVsLTEuNjg3LTFWNy4wNjNjMC0uNjg4LjE4Ny0xLjQzOC41NjItMkM4LjE4NyA0LjQzOCA4Ljc1IDQgOS4zNzUgMy42ODhhMy4zNyAzLjM3IDAgMCAxIDIuMDYyLS4zMTNjLjY4OC4wNjMgMS4zNzUuMzc1IDEuOTM4LjgxM2MwIDAtLjA2My4wNjItLjEyNS4wNjJsLTQgMi4zMTNhLjUuNSAwIDAgMC0uMjUuMjVjLS4wNjMuMTI1LS4wNjMuMTg3LS4wNjMuMzEyem0uODc1LTJMMTIgOS41bDIuMTg3IDEuMjV2Mi41TDEyIDE0LjVsLTIuMTg4LTEuMjV6IiAvPgo8L3N2Zz4='
const ICON_REFLECT_LIST_KEY = 'config/icon-reflect-list'

export const DEFAULT_SETTINGS_URL = './zashboard-settings.json'
export const LUFEI_SELF_USE_SETTINGS_URL =
  'https://raw.githubusercontent.com/liandu2024/little/refs/heads/main/zashboard/ange-clashboard-settings.json'
export const LUFEI_SELF_USE_SETTINGS_FALLBACK_URL = './lufei-clashboard-settings.json'
export const importSettingsUrl = useStorage(IMPORT_SETTINGS_URL_KEY, DEFAULT_SETTINGS_URL)
export const autoImportSettings = useStorage('config/auto-import-settings', false)
export const lufeiSelfUseSettingsEnabled = useStorage(LUFEI_SELF_USE_SETTINGS_ENABLED_KEY, true)

const autoImportSettingsHash = useStorage('cache/auto-import-settings-hash', '')
const lufeiSelfUseSettingsHash = useStorage(LUFEI_SELF_USE_SETTINGS_HASH_KEY, '')
const calculateSettingsHash = async (settings: Record<string, unknown>) => {
  const sortedKeys = Object.keys(settings).sort()
  const hashString = sortedKeys.map((key) => `${key}:${settings[key]}`).join('|')

  let hash = 0
  for (let i = 0; i < hashString.length; i++) {
    const char = hashString.charCodeAt(i)
    hash = (hash << 5) - hash + char
    hash = hash & hash
  }
  return Math.abs(hash).toString(16).padStart(8, '0')
}

const ensureCustomProxyGroupIcon = (settings: Record<string, unknown>) => {
  const rawIconReflectList = settings[ICON_REFLECT_LIST_KEY]
  let iconReflectList: unknown[] = []

  if (Array.isArray(rawIconReflectList)) {
    iconReflectList = rawIconReflectList
  } else if (typeof rawIconReflectList === 'string' && rawIconReflectList.trim()) {
    try {
      const parsedIconReflectList = JSON.parse(rawIconReflectList)

      if (Array.isArray(parsedIconReflectList)) {
        iconReflectList = parsedIconReflectList
      }
    } catch {
      iconReflectList = []
    }
  }

  const nextIconReflectList = iconReflectList
    .filter((item): item is { name: string; icon: string; uuid: string } => {
      return Boolean(
        item &&
        typeof item === 'object' &&
        'name' in item &&
        item.name !== CUSTOM_PROXY_GROUP_ICON_NAME,
      )
    })
    .concat({
      name: CUSTOM_PROXY_GROUP_ICON_NAME,
      icon: CUSTOM_PROXY_GROUP_ICON,
      uuid: CUSTOM_PROXY_GROUP_ICON_UUID,
    })

  settings[ICON_REFLECT_LIST_KEY] = JSON.stringify(nextIconReflectList)

  return settings
}
const fetchSettingsJson = async (url: string) => {
  const response = await fetch(url, {
    cache: 'no-store',
  })

  if (!response.ok) {
    throw new Error(`Failed to fetch settings: ${response.status}`)
  }

  const settings = (await response.json()) as Record<string, unknown>

  if (!settings || typeof settings !== 'object') {
    throw new Error('Invalid settings payload')
  }

  return settings
}

const sanitizeLufeiSelfUseSettings = (settings: Record<string, unknown>) => {
  const sanitized: Record<string, unknown> = {}

  Object.entries(settings).forEach(([key, value]) => {
    const lowerKey = key.toLowerCase()

    if (key.startsWith('setup/')) {
      return
    }

    if (
      lowerKey.includes('password') ||
      lowerKey.includes('secret') ||
      lowerKey.includes('token') ||
      lowerKey.includes('cookie') ||
      lowerKey.includes('session')
    ) {
      return
    }

    sanitized[key] = value
  })

  sanitized[IMPORT_SETTINGS_URL_KEY] = LUFEI_SELF_USE_SETTINGS_URL
  sanitized[LUFEI_SELF_USE_SETTINGS_ENABLED_KEY] = 'true'

  return ensureCustomProxyGroupIcon(sanitized)
}

const applyImportedSettings = async (
  settings: Record<string, unknown>,
  options: {
    force?: boolean
    hashRef: typeof autoImportSettingsHash
    sourceUrl?: string
    keepLufeiSelfUseEnabled?: boolean
  },
) => {
  const force = options.force ?? false
  const newHash = await calculateSettingsHash(settings)

  if (newHash === options.hashRef.value && !force) {
    return false
  }

  showNotification({
    content: 'importing',
  })
  options.hashRef.value = newHash

  const snapshot = stabilizeManagedStorageSnapshot(
    normalizeManagedStorageSnapshot(settings),
    getManagedStorageSnapshot(),
  )

  if (!snapshot[IMPORT_SETTINGS_URL_KEY] && options.sourceUrl) {
    snapshot[IMPORT_SETTINGS_URL_KEY] = options.sourceUrl
  }

  if (options.keepLufeiSelfUseEnabled) {
    snapshot[LUFEI_SELF_USE_SETTINGS_ENABLED_KEY] = 'true'
  }

  applyManagedStorageSnapshot(snapshot)
  try {
    await persistManagedStorageSnapshot(snapshot)
  } catch (error) {
    console.warn('Failed to persist imported settings to server storage', error)
  }
  location.reload()

  return true
}

export const importSettingsFromUrl = async (force = false) => {
  let settings: Record<string, unknown>

  try {
    settings = await fetchSettingsJson(importSettingsUrl.value)
  } catch {
    if (force) {
      showNotification({
        content: 'importFailed',
        params: { url: importSettingsUrl.value },
        type: 'alert-error',
      })
    }

    return
  }

  await applyImportedSettings(settings, {
    force,
    hashRef: autoImportSettingsHash,
    sourceUrl: importSettingsUrl.value,
  })
}

export const importLufeiSelfUseSettings = async (force = false) => {
  let settings: Record<string, unknown>
  let fallbackUsed = false

  try {
    settings = await fetchSettingsJson(LUFEI_SELF_USE_SETTINGS_URL)
  } catch {
    try {
      settings = await fetchSettingsJson(LUFEI_SELF_USE_SETTINGS_FALLBACK_URL)
      fallbackUsed = true
    } catch {
      if (force) {
        showNotification({
          content: '路飞自用设置导入失败',
          type: 'alert-error',
        })
      }

      return
    }
  }

  if (fallbackUsed && force) {
    showNotification({
      content: '远程拉取失败，已使用内置路飞自用设置',
      type: 'alert-warning',
      timeout: 3000,
    })
  }

  settings = sanitizeLufeiSelfUseSettings(settings)

  await applyImportedSettings(settings, {
    force,
    hashRef: lufeiSelfUseSettingsHash,
    sourceUrl: LUFEI_SELF_USE_SETTINGS_URL,
    keepLufeiSelfUseEnabled: true,
  })
}
