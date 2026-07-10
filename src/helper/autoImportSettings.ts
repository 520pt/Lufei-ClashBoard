import { ensureCustomProxyGroupIconInSettings } from '@/helper/customProxyGroupIcon'
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
export {
  CUSTOM_PROXY_GROUP_ICON,
  CUSTOM_PROXY_GROUP_ICON_NAME,
  CUSTOM_PROXY_GROUP_ICON_UUID,
} from '@/helper/customProxyGroupIcon'

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

  return ensureCustomProxyGroupIconInSettings(sanitized)
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
