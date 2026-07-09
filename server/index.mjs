import express from 'express'
import { execFile } from 'node:child_process'
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import { isIP, Socket } from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { Client as SshClient } from 'ssh2'
import { WebSocket, WebSocketServer } from 'ws'
import { parse as parseYaml } from 'yaml'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const rootDir = path.resolve(__dirname, '..')
const distDir = path.join(rootDir, 'dist')
const dataDir = path.join(rootDir, 'data')
const dbPath = process.env.ZASHBOARD_DB_PATH || path.join(dataDir, 'zashboard.sqlite')
const host = process.env.HOST || '0.0.0.0'
const port = Number(process.env.PORT || 2048)
const backgroundImageStorageKey = '__background_image__'
const execFileAsync = promisify(execFile)
const defaultOpenClashUciConfigPath = '/etc/config/openclash'
const defaultOpenClashConfigDir = '/etc/openclash/config'
const openClashUciConfigPath =
  process.env.ZASHBOARD_OPENCLASH_UCI_PATH ||
  process.env.OPENCLASH_UCI_PATH ||
  defaultOpenClashUciConfigPath
const openClashConfigDir =
  process.env.ZASHBOARD_OPENCLASH_CONFIG_DIR ||
  process.env.OPENCLASH_CONFIG_DIR ||
  defaultOpenClashConfigDir
const mihomoBinaryPath =
  process.env.ZASHBOARD_MIHOMO_BIN ||
  (process.platform === 'win32'
    ? path.resolve('.tools/mihomo-bin/mihomo-windows-amd64-compatible.exe')
    : path.resolve('.tools/mihomo-bin/mihomo'))
const ruleSearchTempDir = path.join(dataDir, 'rule-search-temp')
const proxyGroupRulePenetrationCache = new Map()
const proxyGroupRulePenetrationCacheBySignature = new Map()
const PROXY_GROUP_RULE_PENETRATION_CACHE_TTL_MS = 10 * 60 * 1000
const PROXY_GROUP_RULE_PENETRATION_CACHE_LIMIT = 16
const DEFAULT_RULE_PROVIDER_AUTO_REFRESH_CHECK_MS = 60 * 1000
const ACCESS_PASSWORD_ENABLED_KEY = 'config/access-password-enabled'
const ACCESS_PASSWORD_KEY = 'config/access-password'
const SETUP_API_LIST_KEY = 'setup/api-list'
const SETUP_ACTIVE_UUID_KEY = 'setup/active-uuid'
const RULE_PROVIDER_SOURCE_METADATA_KEY = 'rule-provider-cache/source-metadata'
const ACCESS_SESSION_COOKIE_NAME = 'ange_clashboard_access_session'
const ACCESS_SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000
const ACCESS_PASSWORD_REQUIRED_CODE = 'ACCESS_PASSWORD_REQUIRED'
const ACCESS_PASSWORD_INVALID_CODE = 'ACCESS_PASSWORD_INVALID'
const RULE_SOURCE_SSH_REQUIRED_CODE = 'RULE_SOURCE_SSH_REQUIRED'
const CUSTOM_RULES_KEY = 'custom-rules/list'
const CUSTOM_RULES_SETTINGS_KEY = 'custom-rules/settings'
const DEFAULT_CUSTOM_RULE_PROVIDER_NAME = 'LuFei / Custom'
const DEFAULT_CUSTOM_RULE_POLICY_GROUP = '路飞'
const DEFAULT_CUSTOM_RULE_FILE_NAME = 'ziyong.list'
const accessSessionSecret = randomBytes(32).toString('hex')
const configuredRuleProviderAutoRefreshCheckMs = Number.parseInt(
  String(process.env.ZASHBOARD_RULE_PROVIDER_CACHE_AUTO_REFRESH_CHECK_MS || ''),
  10,
)
const RULE_PROVIDER_AUTO_REFRESH_CHECK_MS =
  Number.isFinite(configuredRuleProviderAutoRefreshCheckMs) &&
  configuredRuleProviderAutoRefreshCheckMs >= 5000
    ? configuredRuleProviderAutoRefreshCheckMs
    : DEFAULT_RULE_PROVIDER_AUTO_REFRESH_CHECK_MS
const serviceWorkerCleanupScript = `
self.addEventListener('install', () => {
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const cacheKeys = await caches.keys()
    await Promise.all(cacheKeys.map((cacheKey) => caches.delete(cacheKey)))
    await self.registration.unregister()
    const clientsList = await self.clients.matchAll({
      type: 'window',
      includeUncontrolled: true,
    })
    await Promise.all(
      clientsList.map((client) => {
        if ('navigate' in client) {
          return client.navigate(client.url)
        }

        return Promise.resolve()
      }),
    )
  })())
})
`.trim()
const registerSWCleanupScript = `
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations()
    .then((registrations) =>
      Promise.allSettled(registrations.map((registration) => registration.unregister())),
    )
    .then(() => ('caches' in window ? caches.keys() : Promise.resolve([])))
    .then((cacheKeys) => Promise.allSettled(cacheKeys.map((cacheKey) => caches.delete(cacheKey))))
    .catch(() => {})
}
`.trim()

fs.mkdirSync(path.dirname(dbPath), { recursive: true })
fs.mkdirSync(ruleSearchTempDir, { recursive: true })

const db = new DatabaseSync(dbPath)

db.exec(`
  CREATE TABLE IF NOT EXISTS app_storage (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`)

db.exec(`
  CREATE TABLE IF NOT EXISTS rule_provider_cache (
    name TEXT PRIMARY KEY,
    behavior TEXT NOT NULL,
    format TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_url TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`)

const ruleProviderCacheColumns = db
  .prepare(`PRAGMA table_info(rule_provider_cache)`)
  .all()
  .map((row) => row.name)

if (
  !ruleProviderCacheColumns.includes('source_url') ||
  !ruleProviderCacheColumns.includes('interval_seconds') ||
  !ruleProviderCacheColumns.includes('kind') ||
  !ruleProviderCacheColumns.includes('body')
) {
  db.exec('DROP TABLE IF EXISTS rule_provider_cache')
  db.exec(`
    CREATE TABLE rule_provider_cache (
      name TEXT PRIMARY KEY,
      behavior TEXT NOT NULL,
      format TEXT NOT NULL,
      kind TEXT NOT NULL,
      source_url TEXT NOT NULL,
      interval_seconds INTEGER NOT NULL DEFAULT 0,
      body TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)
}

const getSnapshotStatement = db.prepare(`
  SELECT key, value
  FROM app_storage
  ORDER BY key
`)

const insertSnapshotStatement = db.prepare(`
  INSERT INTO app_storage (key, value, updated_at)
  VALUES (?, ?, CURRENT_TIMESTAMP)
`)

const upsertStorageValueStatement = db.prepare(`
  INSERT INTO app_storage (key, value, updated_at)
  VALUES (?, ?, CURRENT_TIMESTAMP)
  ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    updated_at = CURRENT_TIMESTAMP
`)

const getStorageValueStatement = db.prepare(`
  SELECT value
  FROM app_storage
  WHERE key = ?
`)

const deleteStorageValueStatement = db.prepare(`
  DELETE FROM app_storage
  WHERE key = ?
`)

const clearRuleProviderCacheStatement = db.prepare(`
  DELETE FROM rule_provider_cache
`)

const upsertRuleProviderCacheStatement = db.prepare(`
  INSERT INTO rule_provider_cache (
    name,
    behavior,
    format,
    kind,
    source_url,
    interval_seconds,
    body,
    updated_at
  )
  VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  ON CONFLICT(name) DO UPDATE SET
    behavior = excluded.behavior,
    format = excluded.format,
    kind = excluded.kind,
    source_url = excluded.source_url,
    interval_seconds = excluded.interval_seconds,
    body = excluded.body,
    updated_at = CURRENT_TIMESTAMP
`)

const getCachedRuleProviderStatement = db.prepare(`
  SELECT name, behavior, format, kind, source_url, interval_seconds, body, updated_at
  FROM rule_provider_cache
  ORDER BY name
`)
const getCachedRuleProviderByNameStatement = db.prepare(`
  SELECT name, behavior, format, kind, source_url, interval_seconds, body, updated_at
  FROM rule_provider_cache
  WHERE name = ?
`)
const getRuleProviderCacheTotalCountStatement = db.prepare(`
  SELECT SUM(
    LENGTH(body) - LENGTH(REPLACE(body, CHAR(10), '')) +
    CASE
      WHEN LENGTH(TRIM(body)) = 0 THEN 0
      WHEN body LIKE '%' || CHAR(10) THEN 0
      ELSE 1
    END
  ) AS total
  FROM rule_provider_cache
`)
let activeRuleProviderUpdatePromise = null
let activeRuleProviderUpdateController = null
let ruleProviderAutoRefreshTimer = null
let activeRuleRefreshPromise = null
let activeRuleRefreshController = null
let ruleRefreshRunId = 0
let ruleProviderUpdateState = {
  isUpdating: false,
  totalProviders: 0,
  updatedProviders: 0,
  totalRules: 0,
  errors: 0,
  unsupportedCount: 0,
  cancelled: false,
  completed: false,
}

const createDefaultRuleRefreshState = () => ({
  runId: 0,
  isRefreshing: false,
  scope: 'all',
  providerName: '',
  phase: 'idle',
  totalProviders: 0,
  updatedProviders: 0,
  totalRules: 0,
  errors: 0,
  cancelled: false,
  completed: false,
  lastError: '',
  completedAt: 0,
  updatedAt: Date.now(),
})

let ruleRefreshState = createDefaultRuleRefreshState()

const parseStoredBoolean = (value) => {
  if (typeof value !== 'string') {
    return false
  }

  if (value === 'true' || value === '1') {
    return true
  }

  if (value === 'false' || value === '0' || value === '') {
    return false
  }

  if (value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1) === 'true'
  }

  return false
}

const parseStoredString = (value) => {
  if (typeof value !== 'string' || value === '') {
    return ''
  }

  if (value.startsWith('"') && value.endsWith('"')) {
    try {
      const parsed = JSON.parse(value)

      if (typeof parsed === 'string') {
        return parsed
      }
    } catch {
      // Fall back to the raw value below.
    }
  }

  return value
}

const parseStoredJson = (value, fallback) => {
  if (typeof value !== 'string' || value === '') {
    return fallback
  }

  try {
    return JSON.parse(value)
  } catch {
    return fallback
  }
}

const parseCookies = (cookieHeader) => {
  const cookies = new Map()

  if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) {
    return cookies
  }

  cookieHeader.split(';').forEach((segment) => {
    const separatorIndex = segment.indexOf('=')

    if (separatorIndex === -1) {
      return
    }

    const key = segment.slice(0, separatorIndex).trim()
    const value = segment.slice(separatorIndex + 1).trim()

    if (!key) {
      return
    }

    cookies.set(key, decodeURIComponent(value))
  })

  return cookies
}

const readAccessAuthConfig = () => {
  const enabledRow = getStorageValueStatement.get(ACCESS_PASSWORD_ENABLED_KEY)
  const passwordRow = getStorageValueStatement.get(ACCESS_PASSWORD_KEY)

  return {
    enabled: parseStoredBoolean(enabledRow?.value),
    password: parseStoredString(passwordRow?.value),
  }
}

const readActiveBackendConfig = () => {
  const backendListRow = getStorageValueStatement.get(SETUP_API_LIST_KEY)
  const activeUuidRow = getStorageValueStatement.get(SETUP_ACTIVE_UUID_KEY)
  const backendList = parseStoredJson(backendListRow?.value, [])
  const activeUuid = parseStoredString(activeUuidRow?.value)

  if (!Array.isArray(backendList) || !activeUuid) {
    return null
  }

  return (
    backendList.find(
      (backend) =>
        backend &&
        typeof backend === 'object' &&
        backend.uuid === activeUuid &&
        typeof backend.protocol === 'string' &&
        typeof backend.host === 'string' &&
        typeof backend.port === 'string',
    ) || null
  )
}

const normalizeRuleSourcePlugin = (value) => {
  const normalizedValue = String(value || '')
    .trim()
    .toLowerCase()

  return ['openclash', 'nikki'].includes(normalizedValue) ? normalizedValue : 'auto'
}

const getErrorMessage = (error) => (error instanceof Error ? error.message : String(error))
const getErrorCode = (error) =>
  error && typeof error === 'object' && typeof error.code === 'string' ? error.code : ''
const getErrorDetail = (error) =>
  error && typeof error === 'object' && typeof error.detail === 'string' ? error.detail : ''

const normalizeCustomRuleHost = (value) => {
  const rawValue = String(value || '').trim()

  if (!rawValue) {
    throw new Error('输入不能为空')
  }

  let host = rawValue

  if (/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(rawValue)) {
    return rawValue
  }

  try {
    const parsed = rawValue.includes('://') ? new URL(rawValue) : new URL(`http://${rawValue}`)
    host = parsed.hostname || rawValue
  } catch {
    host = rawValue.split('/')[0]
  }

  return host.trim()
}

const cleanCustomRuleHost = (value) => {
  return String(value || '')
    .trim()
    .replace(/^\*\./, '')
    .replace(/\.$/, '')
    .toLowerCase()
}

const isIpv4Address = (value) => {
  return (
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) &&
    value.split('.').every((item) => Number(item) >= 0 && Number(item) <= 255)
  )
}

const isIpv4Cidr = (value) => {
  const [address, prefix] = String(value || '').split('/')
  const prefixNumber = Number(prefix)

  return (
    isIpv4Address(address) &&
    Number.isInteger(prefixNumber) &&
    prefixNumber >= 0 &&
    prefixNumber <= 32
  )
}

const makeCustomRule = (target, kind = 'auto') => {
  const normalizedKind = String(kind || 'auto')
    .trim()
    .toLowerCase()
    .replace(/-/g, '_')
  const rawValue = String(target || '').trim()

  if (normalizedKind === 'raw') {
    if (!rawValue) {
      throw new Error('输入不能为空')
    }

    return rawValue
  }

  const host = cleanCustomRuleHost(normalizeCustomRuleHost(rawValue))

  if (!host) {
    throw new Error('无法识别域名或 IP')
  }

  if (normalizedKind === 'auto') {
    if (isIpv4Cidr(host)) {
      return `IP-CIDR,${host},no-resolve`
    }

    if (isIpv4Address(host)) {
      return `IP-CIDR,${host}/32,no-resolve`
    }

    return `DOMAIN-SUFFIX,${host}`
  }

  if (normalizedKind === 'domain_suffix') {
    return `DOMAIN-SUFFIX,${host}`
  }

  if (normalizedKind === 'domain') {
    return `DOMAIN,${host}`
  }

  if (normalizedKind === 'ip_cidr') {
    if (isIpv4Cidr(host)) {
      return `IP-CIDR,${host},no-resolve`
    }

    if (isIpv4Address(host)) {
      return `IP-CIDR,${host}/32,no-resolve`
    }
  }

  throw new Error(`不支持的规则类型: ${kind}`)
}

const readCustomRules = () => {
  const row = getStorageValueStatement.get(CUSTOM_RULES_KEY)
  const value = parseStoredJson(row?.value, [])

  return Array.isArray(value)
    ? value.filter((item) => typeof item === 'string' && item.trim()).map((item) => item.trim())
    : []
}

const writeCustomRules = (rules) => {
  const uniqueRules = [...new Set(rules.map((item) => String(item || '').trim()).filter(Boolean))]
  upsertStorageValueStatement.run(CUSTOM_RULES_KEY, JSON.stringify(uniqueRules))

  return uniqueRules
}

const readCustomRuleListText = () => {
  const rules = readCustomRules()

  return rules.length ? `${rules.join('\n')}\n` : ''
}

const readCustomRulesSettings = () => {
  const row = getStorageValueStatement.get(CUSTOM_RULES_SETTINGS_KEY)
  const settings = parseStoredJson(row?.value, {})

  return {
    providerName:
      typeof settings.providerName === 'string' && settings.providerName.trim()
        ? settings.providerName.trim()
        : DEFAULT_CUSTOM_RULE_PROVIDER_NAME,
    policyGroup:
      typeof settings.policyGroup === 'string' && settings.policyGroup.trim()
        ? settings.policyGroup.trim()
        : DEFAULT_CUSTOM_RULE_POLICY_GROUP,
    fileName:
      typeof settings.fileName === 'string' && settings.fileName.trim()
        ? settings.fileName.trim().replace(/^\/+/, '')
        : DEFAULT_CUSTOM_RULE_FILE_NAME,
  }
}

const updateCustomRulesSettings = (settings = {}) => {
  const current = readCustomRulesSettings()
  const next = {
    providerName:
      typeof settings.providerName === 'string' && settings.providerName.trim()
        ? settings.providerName.trim()
        : current.providerName,
    policyGroup:
      typeof settings.policyGroup === 'string' && settings.policyGroup.trim()
        ? settings.policyGroup.trim()
        : current.policyGroup,
    fileName:
      typeof settings.fileName === 'string' && settings.fileName.trim()
        ? settings.fileName.trim().replace(/^\/+/, '')
        : current.fileName,
  }

  upsertStorageValueStatement.run(CUSTOM_RULES_SETTINGS_KEY, JSON.stringify(next))

  return next
}

const buildCustomRuleSnippets = (ruleUrl) => {
  const settings = readCustomRulesSettings()

  return {
    proxyGroupLine: `- {name: ${settings.policyGroup}, <<: *default}`,
    providerLine: `${settings.providerName}: {<<: *class, url: "${ruleUrl}"}`,
    ruleLine: `RULE-SET,${settings.providerName},${settings.policyGroup}`,
  }
}

const normalizeYamlInlineValue = (value, fallback) => {
  const normalizedValue = String(value || '')
    .trim()
    .replace(/[\r\n]/g, ' ')

  return normalizedValue || fallback
}

const escapeYamlDoubleQuotedValue = (value) =>
  String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')

const findTopLevelYamlSectionRange = (lines, sectionName) => {
  const sectionPattern = new RegExp(`^${sectionName}:\\s*(?:#.*)?$`)
  const start = lines.findIndex((line) => sectionPattern.test(line))

  if (start === -1) {
    return null
  }

  const nextSectionIndex = lines.findIndex(
    (line, index) => index > start && /^\S[^:]*:\s*(?:#.*)?$/.test(line),
  )

  return {
    start,
    end: nextSectionIndex === -1 ? lines.length : nextSectionIndex,
  }
}

const insertLineIntoYamlSection = (lines, sectionName, line) => {
  const range = findTopLevelYamlSectionRange(lines, sectionName)

  if (!range) {
    return false
  }

  lines.splice(range.start + 1, 0, line)
  return true
}

const parsedYamlIncludesCustomRule = (parsed, providerName, policyGroup) => {
  const rule = `RULE-SET,${providerName},${policyGroup}`

  return (
    Array.isArray(parsed?.rules) &&
    parsed.rules.some((entry) => String(entry || '').trim() === rule)
  )
}

const parsedYamlIncludesCustomProvider = (parsed, providerName) => {
  return Boolean(parsed?.['rule-providers']?.[providerName])
}

const parsedYamlIncludesCustomProxyGroup = (parsed, policyGroup) => {
  return (
    Array.isArray(parsed?.['proxy-groups']) &&
    parsed['proxy-groups'].some((group) => group?.name === policyGroup)
  )
}

const applyCustomRuleProviderToYamlContent = (content, options = {}) => {
  const providerName = normalizeYamlInlineValue(
    options.providerName,
    DEFAULT_CUSTOM_RULE_PROVIDER_NAME,
  )
  const policyGroup = normalizeYamlInlineValue(
    options.policyGroup,
    DEFAULT_CUSTOM_RULE_POLICY_GROUP,
  )
  const ruleUrl = normalizeYamlInlineValue(options.ruleUrl, '')

  if (!ruleUrl) {
    throw new Error('Custom rule URL is required.')
  }

  const parsed = parseYaml(content) || {}
  const lines = String(content || '')
    .replace(/\r\n/g, '\n')
    .split('\n')
  const result = {
    content: String(content || ''),
    changed: false,
    addedProvider: false,
    addedRule: false,
    addedProxyGroup: false,
  }

  if (!parsedYamlIncludesCustomProxyGroup(parsed, policyGroup)) {
    if (
      !insertLineIntoYamlSection(lines, 'proxy-groups', `  - {name: ${policyGroup}, <<: *default}`)
    ) {
      throw new Error('proxy-groups section was not found in the active YAML.')
    }
    result.addedProxyGroup = true
  }

  if (!parsedYamlIncludesCustomRule(parsed, providerName, policyGroup)) {
    if (!insertLineIntoYamlSection(lines, 'rules', `  - RULE-SET,${providerName},${policyGroup}`)) {
      throw new Error('rules section was not found in the active YAML.')
    }
    result.addedRule = true
  }

  if (!parsedYamlIncludesCustomProvider(parsed, providerName)) {
    if (
      !insertLineIntoYamlSection(
        lines,
        'rule-providers',
        `  ${providerName}: {<<: *class, url: "${escapeYamlDoubleQuotedValue(ruleUrl)}"}`,
      )
    ) {
      throw new Error('rule-providers section was not found in the active YAML.')
    }
    result.addedProvider = true
  }

  result.changed = result.addedProvider || result.addedRule || result.addedProxyGroup
  result.content = lines.join('\n')

  return result
}

const addCustomRule = ({ target, kind = 'auto' }) => {
  const rule = makeCustomRule(target, kind)
  const rules = readCustomRules()

  if (rules.includes(rule)) {
    return {
      rule,
      added: false,
      rules,
    }
  }

  const nextRules = writeCustomRules([...rules, rule])

  return {
    rule,
    added: true,
    rules: nextRules,
  }
}

const deleteCustomRule = (rule) => {
  const rules = readCustomRules()
  const target = String(rule || '').trim()
  const nextRules = rules.filter((item) => item !== target)

  if (nextRules.length === rules.length) {
    return {
      removed: false,
      rules,
    }
  }

  return {
    removed: true,
    rules: writeCustomRules(nextRules),
  }
}

const supportedLocales = ['en-US', 'zh-CN', 'zh-TW', 'ru-RU']
const normalizeLocale = (value = '') => {
  const normalizedValue = String(value || '')
    .trim()
    .toLowerCase()

  if (normalizedValue.startsWith('zh-tw') || normalizedValue.startsWith('zh-hk')) {
    return 'zh-TW'
  }

  if (normalizedValue.startsWith('zh')) {
    return 'zh-CN'
  }

  if (normalizedValue.startsWith('ru')) {
    return 'ru-RU'
  }

  if (normalizedValue.startsWith('en')) {
    return 'en-US'
  }

  return 'zh-CN'
}

const getRequestLocale = (req) => {
  const explicitLocale = req.get('x-zashboard-locale') || ''
  const acceptLanguage = req.get('accept-language') || ''
  const candidate = explicitLocale || acceptLanguage.split(',')[0] || ''

  return normalizeLocale(candidate)
}

const ruleSourceSshRequiredMessages = {
  'en-US': {
    intro:
      'Rule source sync requires an SSH account and password first, and rule source detection must pass.',
    action:
      'Go to "Settings - Backend - Edit backend configuration" > "Rule Source SSH", enter the SSH account and SSH password, choose the correct OpenClash/Nikki, then click "Detect rule source".',
    detailPrefix: 'Current error:',
  },
  'zh-CN': {
    intro: '规则源同步需要先配置 SSH 账号和密码，并确保规则源检测通过。',
    action:
      '请在“设置 - 后端 - 修改后端配置”的“规则源 SSH”中填写 SSH 账号、SSH 密码，选择正确的 OpenClash/Nikki 后点击“检测规则源”。',
    detailPrefix: '当前错误：',
  },
  'zh-TW': {
    intro: '規則源同步需要先配置 SSH 帳號和密碼，並確保規則源檢測通過。',
    action:
      '請在「設定 - 後端 - 修改後端配置」的「規則源 SSH」中填寫 SSH 帳號、SSH 密碼，選擇正確的 OpenClash/Nikki 後點擊「檢測規則源」。',
    detailPrefix: '目前錯誤：',
  },
  'ru-RU': {
    intro:
      'Для синхронизации источников правил сначала укажите SSH-аккаунт и пароль, а затем убедитесь, что проверка источника правил проходит успешно.',
    action:
      'Откройте «Настройки - Бэкенд - Редактировать конфигурацию бэкенда» > «SSH источников правил», введите SSH-аккаунт и SSH-пароль, выберите правильный OpenClash/Nikki и нажмите «Проверить источник правил».',
    detailPrefix: 'Текущая ошибка:',
  },
}

const createRuleSourceSshRequiredMessage = (detail = '', locale = 'zh-CN') => {
  const messages =
    ruleSourceSshRequiredMessages[
      supportedLocales.includes(locale) ? locale : normalizeLocale(locale)
    ] || ruleSourceSshRequiredMessages['zh-CN']
  const message = [messages.intro, messages.action]

  if (detail) {
    message.push(`${messages.detailPrefix}${detail}`)
  }

  return message.join(' ')
}

const getLocalizedErrorMessage = (error, req) => {
  if (getErrorCode(error) === RULE_SOURCE_SSH_REQUIRED_CODE) {
    return createRuleSourceSshRequiredMessage(getErrorDetail(error), getRequestLocale(req))
  }

  return getErrorMessage(error)
}

const createRuleSourceSshRequiredError = (detail = '') => {
  const message = createRuleSourceSshRequiredMessage(detail)
  const error = new Error(message)
  error.code = RULE_SOURCE_SSH_REQUIRED_CODE
  error.detail = detail

  return error
}

const readOpenWrtRuleSourceSshConfig = () => {
  const backend = readActiveBackendConfig()
  const host = parseStoredString(process.env.ZASHBOARD_OPENWRT_SSH_HOST || backend?.host)
  const port =
    Number.parseInt(
      parseStoredString(
        process.env.ZASHBOARD_OPENWRT_SSH_PORT || backend?.ruleSourceSshPort || '22',
      ),
      10,
    ) || 22
  const username = parseStoredString(
    process.env.ZASHBOARD_OPENWRT_SSH_USER ||
      process.env.ZASHBOARD_OPENWRT_SSH_USERNAME ||
      backend?.ruleSourceSshUsername ||
      'root',
  )
  const password = parseStoredString(
    process.env.ZASHBOARD_OPENWRT_SSH_PASSWORD || backend?.ruleSourceSshPassword,
  )
  const plugin = normalizeRuleSourcePlugin(
    process.env.ZASHBOARD_RULE_SOURCE_PLUGIN || backend?.ruleSourcePlugin || 'auto',
  )

  return {
    host,
    port,
    username,
    password,
    plugin,
    configured: Boolean(host && username && password),
  }
}

const sanitizeOpenWrtRuleSourceSshConfig = (config) => ({
  host: config.host || '',
  port: config.port || 22,
  username: config.username || 'root',
  password: config.password || '',
  plugin: normalizeRuleSourcePlugin(config.plugin || 'auto'),
  configured: Boolean(config.host && config.username && config.password),
})

const normalizeOpenWrtRuleSourceSshConfigInput = (input = {}) => {
  const port = Number.parseInt(String(input.port || input.ruleSourceSshPort || '22'), 10)

  return {
    host: String(input.host || '').trim(),
    port: Number.isFinite(port) && port > 0 ? port : 22,
    username:
      String(input.username || input.user || input.ruleSourceSshUsername || 'root').trim() ||
      'root',
    password: String(input.password || input.ruleSourceSshPassword || ''),
    plugin: normalizeRuleSourcePlugin(input.plugin || input.ruleSourcePlugin || 'auto'),
  }
}

const saveOpenWrtRuleSourceSshConfig = (config) => {
  const backendListRow = getStorageValueStatement.get(SETUP_API_LIST_KEY)
  const activeUuidRow = getStorageValueStatement.get(SETUP_ACTIVE_UUID_KEY)
  const backendList = parseStoredJson(backendListRow?.value, [])
  const activeUuid = parseStoredString(activeUuidRow?.value)

  if (!Array.isArray(backendList) || !activeUuid) {
    throw new Error('No active backend configured')
  }

  const backendIndex = backendList.findIndex((backend) => backend?.uuid === activeUuid)

  if (backendIndex === -1) {
    throw new Error('No active backend configured')
  }

  backendList[backendIndex] = {
    ...backendList[backendIndex],
    ruleSourcePlugin: normalizeRuleSourcePlugin(config.plugin || 'auto'),
    ruleSourceSshPort: String(config.port || 22),
    ruleSourceSshUsername: config.username || 'root',
    ruleSourceSshPassword: config.password || '',
  }

  upsertStorageValueStatement.run(SETUP_API_LIST_KEY, JSON.stringify(backendList))
}

const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`

const connectOpenWrtSsh = (config) => {
  return new Promise((resolve, reject) => {
    const client = new SshClient()
    let settled = false
    const settle = (callback, value) => {
      if (settled) return
      settled = true
      callback(value)
    }

    client
      .on('ready', () => settle(resolve, client))
      .on('keyboard-interactive', (_name, _instructions, _lang, prompts, finish) => {
        finish(prompts.map(() => config.password))
      })
      .on('close', () => {
        settle(reject, new Error('OpenWrt SSH connection closed before it was ready.'))
      })
      .on('error', (error) => settle(reject, error))
      .connect({
        host: config.host,
        port: config.port || 22,
        username: config.username || 'root',
        password: config.password,
        tryKeyboard: true,
        readyTimeout: 10000,
      })
  })
}

const sshExec = (client, command, options = {}) => {
  const maxBuffer = options.maxBuffer || 8 * 1024 * 1024

  return new Promise((resolve, reject) => {
    client.exec(command, (error, stream) => {
      if (error) {
        reject(error)
        return
      }

      let stdout = ''
      let stderr = ''
      let stdoutBytes = 0
      let stderrBytes = 0

      stream
        .on('error', reject)
        .on('close', (code) => {
          resolve({
            code,
            stdout,
            stderr,
          })
        })
        .on('data', (chunk) => {
          stdoutBytes += chunk.length
          if (stdoutBytes > maxBuffer) {
            stream.destroy(new Error('SSH command output is too large'))
            return
          }
          stdout += chunk.toString('utf8')
        })
        .stderr.on('data', (chunk) => {
          stderrBytes += chunk.length
          if (stderrBytes > maxBuffer) {
            stream.destroy(new Error('SSH command error output is too large'))
            return
          }
          stderr += chunk.toString('utf8')
        })
    })
  })
}

const withOpenWrtSshClient = async (config, callback) => {
  if (!config.host || !config.username || !config.password) {
    throw new Error('OpenWrt SSH is not configured. Set host, username and password first.')
  }

  const client = await connectOpenWrtSsh(config)

  try {
    return await callback(client)
  } finally {
    client.end()
  }
}

const remoteFileExists = async (client, filePath) => {
  const result = await sshExec(client, `[ -f ${shellQuote(filePath)} ] && printf 1 || printf 0`, {
    maxBuffer: 1024,
  })

  return result.stdout.trim() === '1'
}

const readRemoteFile = async (client, filePath) => {
  const result = await sshExec(client, `cat ${shellQuote(filePath)}`)

  if (result.code !== 0) {
    throw new Error(result.stderr.trim() || `Failed to read remote file: ${filePath}`)
  }

  return result.stdout
}

const writeRemoteFile = async (client, filePath, content) => {
  await new Promise((resolve, reject) => {
    client.sftp((error, sftp) => {
      if (error) {
        reject(error)
        return
      }

      const stream = sftp.createWriteStream(filePath, { encoding: 'utf8' })

      stream
        .on('error', (streamError) => {
          sftp.end?.()
          reject(streamError)
        })
        .on('close', () => {
          sftp.end?.()
          resolve()
        })

      stream.end(content)
    })
  })
}

const remotePathExists = async (client, filePath) => {
  const result = await sshExec(client, `[ -e ${shellQuote(filePath)} ] && printf 1 || printf 0`, {
    maxBuffer: 1024,
  })

  return result.stdout.trim() === '1'
}

const dedupeStrings = (values) => [
  ...new Set(values.map((value) => String(value || '').trim()).filter(Boolean)),
]

const isRemoteYamlPath = (value) => /^\/\S+\.ya?ml$/i.test(String(value || '').trim())

function extractRemoteYamlConfigPathsFromText(content) {
  const candidates = []
  const patterns = [
    /(?:^|\s)(?:-f|--config|-config)\s+['"]?(\/[^\s'"]+\.ya?ml)['"]?(?=\s|$)/gi,
    /(?:^|\s)(?:-f|--config|-config)=['"]?(\/[^\s'"]+\.ya?ml)['"]?(?=\s|$)/gi,
    /['"]?(\/[^\s'"]+\.ya?ml)['"]?(?=\s|$)/gi,
  ]

  patterns.forEach((pattern) => {
    for (const match of String(content || '').matchAll(pattern)) {
      if (isRemoteYamlPath(match[1])) {
        candidates.push(match[1])
      }
    }
  })

  return dedupeStrings(candidates)
}

function extractRemoteYamlConfigPathsFromUci(content) {
  const candidates = []

  String(content || '')
    .split(/\r?\n/)
    .forEach((line) => {
      const match = /^\s*(?:option|list)\s+\S+(?:\s+|=)(.+?)\s*$/.exec(line)

      if (!match) {
        return
      }

      const value = parseUciValue(match[1])

      if (isRemoteYamlPath(value)) {
        candidates.push(value)
      }
    })

  return dedupeStrings([...candidates, ...extractRemoteYamlConfigPathsFromText(content)])
}

const isOpenClashOwnedPath = (value) =>
  /(?:^|\/)openclash(?:\/|$)/i.test(String(value || '').trim())

const isNikkiProcessLine = (line) => /\bnikki\b|\/nikki(?:\/|$)/i.test(String(line || ''))

function extractNikkiYamlConfigPathsFromProcessList(content) {
  return dedupeStrings(
    String(content || '')
      .split(/\r?\n/)
      .filter(isNikkiProcessLine)
      .flatMap((line) => extractRemoteYamlConfigPathsFromText(line))
      .filter((candidate) => !isOpenClashOwnedPath(candidate)),
  )
}

const setRuleRefreshState = (partial) => {
  ruleRefreshState = {
    ...ruleRefreshState,
    ...partial,
    updatedAt: Date.now(),
  }
}

const createAccessSessionToken = (password) => {
  return createHmac('sha256', accessSessionSecret).update(password).digest('base64url')
}

const safeTokenEquals = (left, right) => {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false
  }

  const leftBuffer = Buffer.from(left)
  const rightBuffer = Buffer.from(right)

  if (leftBuffer.length !== rightBuffer.length) {
    return false
  }

  return timingSafeEqual(leftBuffer, rightBuffer)
}

const isAccessSessionAuthenticated = (cookieHeader, password) => {
  if (!password) {
    return false
  }

  const token = parseCookies(cookieHeader).get(ACCESS_SESSION_COOKIE_NAME)

  if (!token) {
    return false
  }

  return safeTokenEquals(token, createAccessSessionToken(password))
}

const getRequestAccessAuthStatus = (req) => {
  const config = readAccessAuthConfig()

  if (!config.enabled) {
    return {
      enabled: false,
      authenticated: true,
    }
  }

  return {
    enabled: true,
    authenticated: isAccessSessionAuthenticated(req.headers.cookie, config.password),
  }
}

const getUpgradeAccessAuthStatus = (request) => {
  const config = readAccessAuthConfig()

  if (!config.enabled) {
    return {
      enabled: false,
      authenticated: true,
    }
  }

  return {
    enabled: true,
    authenticated: isAccessSessionAuthenticated(request.headers.cookie, config.password),
  }
}

const setAccessSessionCookie = (res, password) => {
  res.cookie(ACCESS_SESSION_COOKIE_NAME, createAccessSessionToken(password), {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: ACCESS_SESSION_MAX_AGE_MS,
    path: '/',
  })
}

const clearAccessSessionCookie = (res) => {
  res.clearCookie(ACCESS_SESSION_COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
  })
}

const sendAccessPasswordRequired = (res) => {
  res.setHeader('Cache-Control', 'no-store')
  clearAccessSessionCookie(res)
  res.status(401).json({
    code: ACCESS_PASSWORD_REQUIRED_CODE,
    message: 'Access password authentication required',
    enabled: true,
    authenticated: false,
  })
}

const readSnapshot = () => {
  const snapshot = {}

  for (const row of getSnapshotStatement.all()) {
    if (row.key === backgroundImageStorageKey) continue
    snapshot[row.key] = row.value
  }

  return snapshot
}

const replaceSnapshot = (entries) => {
  db.exec('BEGIN')

  try {
    db.prepare('DELETE FROM app_storage WHERE key != ?').run(backgroundImageStorageKey)

    for (const [key, value] of Object.entries(entries)) {
      insertSnapshotStatement.run(key, value)
    }

    db.exec('COMMIT')
  } catch (error) {
    db.exec('ROLLBACK')
    throw error
  }
}

const isValidEntries = (entries) => {
  return (
    entries &&
    typeof entries === 'object' &&
    !Array.isArray(entries) &&
    Object.entries(entries).every(
      ([key, value]) => typeof key === 'string' && typeof value === 'string',
    )
  )
}

function stripUciInlineComment(value) {
  let quote = ''
  let escaped = false

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]

    if (escaped) {
      escaped = false
      continue
    }

    if (quote) {
      if (quote === '"' && character === '\\') {
        escaped = true
        continue
      }

      if (character === quote) {
        quote = ''
      }

      continue
    }

    if (character === "'" || character === '"') {
      quote = character
      continue
    }

    if (character === '#') {
      return value.slice(0, index).trim()
    }
  }

  return value.trim()
}

function parseUciValue(value) {
  const normalizedValue = stripUciInlineComment(String(value || '')).trim()

  if (!normalizedValue) {
    return ''
  }

  const quote = normalizedValue[0]

  if (quote === "'" || quote === '"') {
    let parsedValue = ''
    let escaped = false

    for (let index = 1; index < normalizedValue.length; index += 1) {
      const character = normalizedValue[index]

      if (escaped) {
        parsedValue += character
        escaped = false
        continue
      }

      if (quote === '"' && character === '\\') {
        escaped = true
        continue
      }

      if (character === quote) {
        return parsedValue.trim()
      }

      parsedValue += character
    }

    return parsedValue.trim()
  }

  return normalizedValue.split(/\s+/)[0] || ''
}

function getOpenClashConfigPathFromUci(content) {
  const configPaths = []

  String(content || '')
    .split(/\r?\n/)
    .forEach((line) => {
      const match = /^\s*option\s+config_path(?:\s+|=)(.+?)\s*$/.exec(line)

      if (!match) {
        return
      }

      const configPath = parseUciValue(match[1])

      if (configPath) {
        configPaths.push(configPath)
      }
    })

  return configPaths.at(-1) || ''
}

function resolveOpenClashConfigPathValue(configPath, options = {}) {
  const normalizedConfigPath = String(configPath || '').trim()

  if (!normalizedConfigPath) {
    return ''
  }

  const pathApi = options.pathApi || path.posix

  if (pathApi.isAbsolute(normalizedConfigPath)) {
    return pathApi.normalize(normalizedConfigPath)
  }

  const configDir = options.configDir || openClashConfigDir
  const uciConfigPath = options.uciConfigPath || openClashUciConfigPath
  const candidates =
    options.preferExisting === false
      ? [pathApi.resolve(configDir, normalizedConfigPath)]
      : [
          pathApi.resolve(configDir, normalizedConfigPath),
          pathApi.resolve(pathApi.dirname(uciConfigPath), normalizedConfigPath),
        ]
  const existingCandidate =
    options.preferExisting === false ? '' : candidates.find((candidate) => fs.existsSync(candidate))

  return existingCandidate || candidates[0]
}

function resolveOpenClashConfigPathFromUci(content, options = {}) {
  return resolveOpenClashConfigPathValue(getOpenClashConfigPathFromUci(content), options)
}

function extractRuleProviderEntriesFromContent(content) {
  const parsed = parseYaml(content)
  const providers = parsed?.['rule-providers']

  if (!providers || typeof providers !== 'object') {
    return []
  }

  return Object.entries(providers)
    .map(([name, provider]) => {
      if (!provider || typeof provider !== 'object') {
        return null
      }

      const url = normalizeRuleProviderUrl(provider.url)

      if (typeof url !== 'string' || !url) {
        return null
      }

      return {
        name,
        behavior: typeof provider.behavior === 'string' ? provider.behavior : '',
        format: typeof provider.format === 'string' ? provider.format : '',
        interval:
          typeof provider.interval === 'number'
            ? provider.interval
            : Number.parseInt(String(provider.interval || '0'), 10) || 0,
        url,
      }
    })
    .filter(Boolean)
}

const getNikkiRuleSourceConfigPathCandidates = async (client) => {
  const processResult = await sshExec(client, 'ps ww || ps w || ps', {
    maxBuffer: 256 * 1024,
  }).catch(() => null)
  const processCandidates = extractNikkiYamlConfigPathsFromProcessList(processResult?.stdout || '')
  const uciCandidates = []

  if (await remoteFileExists(client, '/etc/config/nikki')) {
    const uciContent = await readRemoteFile(client, '/etc/config/nikki')
    uciCandidates.push(
      ...extractRemoteYamlConfigPathsFromUci(uciContent).filter(
        (candidate) => !isOpenClashOwnedPath(candidate),
      ),
    )
  }

  return dedupeStrings([
    ...processCandidates,
    ...uciCandidates,
    '/etc/nikki/run/config.yaml',
    '/etc/nikki/run/config.yml',
    '/var/etc/nikki/config.yaml',
    '/var/run/nikki/config.yaml',
    '/tmp/etc/nikki/config.yaml',
  ])
}

const detectNikkiRuleSourceFromOpenWrtClient = async (client) => {
  const configPathCandidates = await getNikkiRuleSourceConfigPathCandidates(client)
  const checkedExistingPaths = []

  for (const configPath of configPathCandidates) {
    if (!(await remoteFileExists(client, configPath))) {
      continue
    }

    checkedExistingPaths.push(configPath)

    const content = await readRemoteFile(client, configPath)
    const providers = extractRuleProviderEntriesFromContent(content)

    if (providers.length === 0) {
      continue
    }

    return {
      plugin: 'nikki',
      configPath,
      providers,
    }
  }

  if (
    checkedExistingPaths.length > 0 ||
    (await remoteFileExists(client, '/etc/config/nikki')) ||
    (await remotePathExists(client, '/etc/nikki'))
  ) {
    throw new Error(
      `Nikki detected, but no readable YAML with rule-providers was found${
        checkedExistingPaths.length > 0 ? `: ${checkedExistingPaths.join(', ')}` : ''
      }.`,
    )
  }

  return null
}

const detectOpenClashRuleSourceFromOpenWrtClient = async (client) => {
  if (!(await remoteFileExists(client, openClashUciConfigPath))) {
    return null
  }

  const uciContent = await readRemoteFile(client, openClashUciConfigPath)
  const configPath = resolveOpenClashConfigPathFromUci(uciContent, {
    configDir: openClashConfigDir,
    uciConfigPath: openClashUciConfigPath,
    pathApi: path.posix,
    preferExisting: false,
  })

  if (!configPath) {
    throw new Error('OpenClash detected, but option config_path is missing.')
  }

  if (!(await remoteFileExists(client, configPath))) {
    throw new Error(`OpenClash config_path file does not exist: ${configPath}`)
  }

  const content = await readRemoteFile(client, configPath)

  return {
    plugin: 'openclash',
    configPath,
    providers: extractRuleProviderEntriesFromContent(content),
  }
}

const collectRuleSourceSnapshotsFromOpenWrtClient = async (client, requestedPlugin = 'auto') => {
  const plugin = normalizeRuleSourcePlugin(requestedPlugin)
  const snapshots = []
  const errors = []
  const detectors = [
    ['openclash', detectOpenClashRuleSourceFromOpenWrtClient],
    ['nikki', detectNikkiRuleSourceFromOpenWrtClient],
  ].filter(([name]) => plugin === 'auto' || plugin === name)

  for (const [name, detector] of detectors) {
    try {
      const snapshot = await detector(client)

      if (snapshot) {
        snapshots.push(snapshot)
      }
    } catch (error) {
      errors.push({
        plugin: name,
        message: error instanceof Error ? error.message : String(error),
      })
    }
  }

  return {
    plugin,
    snapshots,
    errors,
  }
}

const detectRuleSourceFromOpenWrtClient = async (client, requestedPlugin = 'auto') => {
  const { plugin, snapshots, errors } = await collectRuleSourceSnapshotsFromOpenWrtClient(
    client,
    requestedPlugin,
  )

  if (snapshots.length > 0) {
    return {
      ...snapshots[0],
      selectedPlugin: snapshots[0].plugin,
      availablePlugins: snapshots.map((snapshot) => snapshot.plugin),
      pluginErrors: errors,
    }
  }

  if (errors.length > 0) {
    throw new Error(errors.map((entry) => `${entry.plugin}: ${entry.message}`).join('; '))
  }

  throw new Error(
    plugin === 'auto'
      ? 'OpenClash or Nikki was not detected on the OpenWrt host.'
      : `${plugin} was not detected on the OpenWrt host.`,
  )
}

const getOpenWrtRuleSourceSnapshot = async (options = {}) => {
  const config = options.config || readOpenWrtRuleSourceSshConfig()

  if (!config.configured && !options.required) {
    return null
  }

  return await withOpenWrtSshClient(config, (client) =>
    detectRuleSourceFromOpenWrtClient(client, config.plugin),
  )
}

const assertRuleSourceReadyForSync = async () => {
  const config = readOpenWrtRuleSourceSshConfig()

  if (!config.configured) {
    throw createRuleSourceSshRequiredError()
  }

  try {
    return await getOpenWrtRuleSourceSnapshot({
      config,
      required: true,
    })
  } catch (error) {
    throw createRuleSourceSshRequiredError(getErrorMessage(error))
  }
}

const getRemoteYamlBackupPath = (configPath) => {
  const timestamp = new Date()
    .toISOString()
    .replace(/[-:.TZ]/g, '')
    .slice(0, 14)

  return `${configPath}.lufei-${timestamp}.bak`
}

const applyCustomRuleProviderToOpenWrtYaml = async ({ ruleUrl }) => {
  const config = readOpenWrtRuleSourceSshConfig()

  if (!config.configured) {
    throw createRuleSourceSshRequiredError()
  }

  return await withOpenWrtSshClient(config, async (client) => {
    const snapshot = await detectRuleSourceFromOpenWrtClient(client, config.plugin)
    const settings = readCustomRulesSettings()
    const currentContent = await readRemoteFile(client, snapshot.configPath)
    const applyResult = applyCustomRuleProviderToYamlContent(currentContent, {
      providerName: settings.providerName,
      policyGroup: settings.policyGroup,
      ruleUrl,
    })
    let backupPath = ''

    if (applyResult.changed) {
      backupPath = getRemoteYamlBackupPath(snapshot.configPath)
      const backupResult = await sshExec(
        client,
        `cp ${shellQuote(snapshot.configPath)} ${shellQuote(backupPath)}`,
      )

      if (backupResult.code !== 0) {
        throw new Error(
          backupResult.stderr.trim() || `Failed to backup remote YAML: ${snapshot.configPath}`,
        )
      }

      const tempPath = `${snapshot.configPath}.lufei-${Date.now()}.tmp`
      await writeRemoteFile(client, tempPath, applyResult.content)

      const moveResult = await sshExec(
        client,
        `mv ${shellQuote(tempPath)} ${shellQuote(snapshot.configPath)}`,
      )

      if (moveResult.code !== 0) {
        await sshExec(client, `rm -f ${shellQuote(tempPath)}`).catch(() => null)
        throw new Error(
          moveResult.stderr.trim() || `Failed to update remote YAML: ${snapshot.configPath}`,
        )
      }
    }

    return {
      ok: true,
      plugin: snapshot.plugin,
      configPath: snapshot.configPath,
      backupPath,
      changed: applyResult.changed,
      addedProvider: applyResult.addedProvider,
      addedRule: applyResult.addedRule,
      addedProxyGroup: applyResult.addedProxyGroup,
    }
  })
}

const getLocalPrivateIpv4Interfaces = () => {
  return Object.values(os.networkInterfaces())
    .flat()
    .filter(Boolean)
    .filter((item) => item.family === 'IPv4' && !item.internal)
    .map((item) => item.address)
    .filter((address) => {
      return (
        /^10\./.test(address) ||
        /^192\.168\./.test(address) ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(address)
      )
    })
}

const getIpv4Subnet24Prefix = (address) => {
  const parts = String(address || '').split('.')

  if (parts.length !== 4) {
    return ''
  }

  return parts.slice(0, 3).join('.')
}

const getOpenWrtLanScanTargets = (addresses = getLocalPrivateIpv4Interfaces()) => {
  const targets = new Set()

  addresses.forEach((address) => {
    const prefix = getIpv4Subnet24Prefix(address)

    if (!prefix) {
      return
    }

    ;[1, 2, 254].forEach((last) => targets.add(`${prefix}.${last}`))

    for (let last = 1; last <= 254; last += 1) {
      targets.add(`${prefix}.${last}`)
    }
  })

  addresses.forEach((address) => targets.delete(address))

  return [...targets]
}

const OPENWRT_WEB_DISCOVERY_PORTS = [80, 8080, 443]
const OPENWRT_SSH_DISCOVERY_PORTS = [22, 2222]
const CLASH_CONTROLLER_DISCOVERY_PORTS = [9090, 9091, 9092, 9093, 9097, 19090, 19091]

const checkTcpPort = (hostValue, portValue, timeoutMs = 450) => {
  return new Promise((resolve) => {
    const socket = new Socket()
    let settled = false
    const settle = (value) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(value)
    }

    socket.setTimeout(timeoutMs)
    socket.once('connect', () => settle(true))
    socket.once('timeout', () => settle(false))
    socket.once('error', () => settle(false))
    socket.connect(portValue, hostValue)
  })
}

const getOpenPorts = async (hostValue, ports) => {
  const states = await Promise.all(ports.map((portValue) => checkTcpPort(hostValue, portValue)))

  return ports.filter((_portValue, index) => states[index])
}

const fetchTextWithTimeout = async (url, timeoutMs = 900) => {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      redirect: 'manual',
    })
    const text = await response.text().catch(() => '')

    return {
      ok: true,
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      text,
    }
  } catch {
    return {
      ok: false,
      status: 0,
      headers: {},
      text: '',
    }
  } finally {
    clearTimeout(timer)
  }
}

const getOpenWrtWebUrl = (hostValue, portValue, pathname = '/') => {
  if (portValue === 443) {
    return `https://${hostValue}${pathname}`
  }

  if (portValue === 80) {
    return `http://${hostValue}${pathname}`
  }

  return `http://${hostValue}:${portValue}${pathname}`
}

const detectOpenWrtHostCandidate = async (hostValue) => {
  const [openWebPorts, openSshPorts, openControllerPorts] = await Promise.all([
    getOpenPorts(hostValue, OPENWRT_WEB_DISCOVERY_PORTS),
    getOpenPorts(hostValue, OPENWRT_SSH_DISCOVERY_PORTS),
    getOpenPorts(hostValue, CLASH_CONTROLLER_DISCOVERY_PORTS),
  ])
  const httpOpen = openWebPorts.length > 0
  const sshOpen = openSshPorts.length > 0
  const controllerOpen = openControllerPorts.length > 0

  if (!httpOpen && !sshOpen && !controllerOpen) {
    return null
  }

  const webResults = httpOpen
    ? await Promise.all(
        openWebPorts.flatMap((portValue) => [
          fetchTextWithTimeout(getOpenWrtWebUrl(hostValue, portValue, '/cgi-bin/luci')),
          fetchTextWithTimeout(getOpenWrtWebUrl(hostValue, portValue, '/')),
        ]),
      )
    : []
  const httpText = webResults
    .map((result) => result.text || '')
    .join('\n')
    .toLowerCase()
  const httpHeaders = webResults.reduce(
    (headers, result) => ({ ...headers, ...result.headers }),
    {},
  )
  const serverHeader = String(httpHeaders.server || '').toLowerCase()
  const hasOpenWrtHint =
    httpText.includes('openwrt') ||
    httpText.includes('luci') ||
    serverHeader.includes('openwrt') ||
    serverHeader.includes('uhttpd')
  const controllerPort = openControllerPorts[0] || 9090
  const score =
    (hasOpenWrtHint ? 80 : 0) + (sshOpen ? 12 : 0) + (httpOpen ? 8 : 0) + (controllerOpen ? 20 : 0)

  if (score < 20) {
    return null
  }

  return {
    host: hostValue,
    label: hasOpenWrtHint ? `OpenWrt ${hostValue}` : `疑似 OpenWrt ${hostValue}`,
    protocol: 'http',
    port: String(controllerPort),
    ruleSourceSshPort: sshOpen ? String(openSshPorts[0]) : '',
    ruleSourceSshUsername: 'root',
    ruleSourcePlugin: 'auto',
    httpOpen,
    sshOpen,
    openWebPorts,
    openSshPorts,
    controllerOpen,
    controllerPort,
    controllerPorts: openControllerPorts,
    hasOpenWrtHint,
    score,
  }
}

const runWithConcurrency = async (items, limit, worker) => {
  const results = []
  let cursor = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const item = items[cursor]
      cursor += 1
      results.push(await worker(item))
    }
  })

  await Promise.all(workers)

  return results
}

const discoverOpenWrtLanHosts = async (options = {}) => {
  const localAddresses = getLocalPrivateIpv4Interfaces()
  const targets = getOpenWrtLanScanTargets(localAddresses).slice(0, options.limit || 512)
  const scannedAt = Date.now()
  const results = await runWithConcurrency(
    targets,
    options.concurrency || 64,
    detectOpenWrtHostCandidate,
  )
  const candidates = results
    .filter(Boolean)
    .sort((a, b) => b.score - a.score || a.host.localeCompare(b.host, undefined, { numeric: true }))

  return {
    ok: true,
    localAddresses,
    scannedCount: targets.length,
    durationMs: Date.now() - scannedAt,
    candidates,
  }
}

const getRuleProviderKind = (url, format, behavior) => {
  const normalizedUrl = url.toLowerCase()
  const normalizedFormat = format.toLowerCase()
  const normalizedBehavior = behavior.toLowerCase()

  if (
    normalizedUrl.endsWith('.mrs') ||
    normalizedFormat === 'mrs' ||
    normalizedFormat === 'mrsrule'
  ) {
    if (normalizedBehavior === 'ipcidr' || normalizedUrl.includes('/geoip/')) {
      return 'mrs-ip'
    }

    return 'mrs-domain'
  }

  return 'text'
}

const normalizeDomain = (domain) =>
  domain.trim().toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '')
const normalizeKeyword = (value) => value.trim().toLowerCase()
function normalizeRuleProviderUrl(value) {
  return String(value || '')
    .trim()
    .replace(/^(https?:\/\/)(?:gh-)?https?:\/\//i, '$1')
}
const RULE_TYPE_ALIAS_MAP = new Map([
  ['DOMAIN', 'DOMAIN'],
  ['DOMAINSUFFIX', 'DOMAIN-SUFFIX'],
  ['DOMAINKEYWORD', 'DOMAIN-KEYWORD'],
  ['IPCIDR', 'IP-CIDR'],
  ['IPCIDR6', 'IP-CIDR6'],
  ['SRCIP', 'SRC-IP'],
  ['SRCIPCIDR', 'SRC-IP-CIDR'],
  ['SRCIPCIDR6', 'SRC-IP-CIDR6'],
  ['DSTPORT', 'DST-PORT'],
  ['SRCPORT', 'SRC-PORT'],
  ['INPORT', 'IN-PORT'],
  ['GEOIP', 'GEOIP'],
  ['RULESET', 'RULE-SET'],
  ['FINAL', 'FINAL'],
  ['MATCH', 'MATCH'],
])

const normalizeRuleTypeName = (value) => {
  const normalizedKey = String(value || '')
    .trim()
    .replace(/[^a-z0-9]/gi, '')
    .toUpperCase()

  return (
    RULE_TYPE_ALIAS_MAP.get(normalizedKey) ||
    String(value || '')
      .trim()
      .toUpperCase()
  )
}

const getRuleEntryFamily = (type) => {
  if (['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].includes(type)) {
    return 'domain'
  }

  if (['IP-CIDR', 'IP-CIDR6', 'SRC-IP', 'SRC-IP-CIDR', 'SRC-IP-CIDR6', 'GEOIP'].includes(type)) {
    return 'ip'
  }

  if (['DST-PORT', 'SRC-PORT', 'IN-PORT'].includes(type)) {
    return 'port'
  }

  return 'other'
}

const buildRuleEntry = (type, content, params = [], options = {}) => {
  const normalizedType = normalizeRuleTypeName(type)
  const normalizedContent = String(content || '').trim()
  const normalizedParams = params.map((param) => String(param || '').trim()).filter(Boolean)
  const raw =
    options.raw ||
    [normalizedType, normalizedContent, ...normalizedParams].filter(Boolean).join(',')

  return {
    type: normalizedType,
    family: getRuleEntryFamily(normalizedType),
    content: normalizedContent,
    params: normalizedParams.join(', '),
    raw,
    source: options.source || '',
    line: Number.isInteger(options.line) ? options.line : null,
  }
}

const parseRuleEntryFromTextLine = (rawLine, index = null, source = '') => {
  const line = String(rawLine || '').trim()

  if (!line || line.startsWith('#') || line.startsWith('//') || /^payload\s*:/i.test(line)) {
    return null
  }

  const normalizedLine = line.startsWith('- ') ? line.slice(2).trim() : line

  if (!normalizedLine) {
    return null
  }

  if (/^(domain|suffix|keyword|ip-cidr|ip-cidr6):/i.test(normalizedLine)) {
    const [, key, value] = normalizedLine.match(/^([^:]+):\s*(.+)$/) || []

    if (!key || !value) {
      return null
    }

    const canonicalType = normalizeRuleTypeName(key)

    return buildRuleEntry(canonicalType, value, [], {
      raw: `${canonicalType},${value.trim()}`,
      source,
      line: index,
    })
  }

  if (normalizedLine.startsWith('+.')) {
    const value = normalizedLine.slice(2).trim()

    return buildRuleEntry('DOMAIN-SUFFIX', value, [], {
      raw: `DOMAIN-SUFFIX,${value}`,
      source,
      line: index,
    })
  }

  if (!normalizedLine.includes(',')) {
    if (parseIpCidr(normalizedLine)) {
      return buildRuleEntry('IP-CIDR', normalizedLine, [], {
        raw: `IP-CIDR,${normalizedLine}`,
        source,
        line: index,
      })
    }

    return buildRuleEntry('DOMAIN', normalizedLine, [], {
      raw: `DOMAIN,${normalizedLine}`,
      source,
      line: index,
    })
  }

  const parts = normalizedLine.split(',').map((part) => part.trim())
  const canonicalType = normalizeRuleTypeName(parts[0])
  const content = parts[1] || ''
  const params = parts.slice(2)

  if (!canonicalType || !content) {
    return null
  }

  return buildRuleEntry(canonicalType, content, params, {
    raw: [canonicalType, content, ...params].filter(Boolean).join(','),
    source,
    line: index,
  })
}

const parseRuleEntriesFromBody = (body, source = '') => {
  const entries = []
  const lines = String(body || '').split(/\r?\n/)

  lines.forEach((line, index) => {
    const entry = parseRuleEntryFromTextLine(line, index + 1, source)

    if (entry) {
      entries.push(entry)
    }
  })

  return entries
}

const isRuleEnabled = (rule) => {
  if (rule?.extra) {
    return !rule.extra.disabled
  }

  return !rule?.disabled
}

const parseDirectControllerRuleEntry = (rule) => {
  const normalizedType = normalizeRuleTypeName(rule?.type)

  if (!normalizedType || normalizedType === 'RULE-SET') {
    return null
  }

  const payloadParts = String(rule?.payload || '')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
  const content = payloadParts[0] || ''
  const params = payloadParts.slice(1)
  const proxy = String(rule?.proxy || '').trim()
  const normalizedParams = proxy ? [...params, proxy] : params

  if (!content && normalizedType !== 'MATCH' && normalizedType !== 'FINAL') {
    return null
  }

  return buildRuleEntry(normalizedType, content, normalizedParams, {
    raw: [normalizedType, content, ...normalizedParams].filter(Boolean).join(','),
    source: 'controller',
    line: Number.isInteger(rule?.index) ? rule.index + 1 : null,
  })
}

const PROXY_GROUP_PRE_CUSTOM_KEY = '__custom_pre__'
const PROXY_GROUP_POST_CUSTOM_KEY = '__custom_post__'

const getProxyGroupCustomModeFromGroupName = (groupName) => {
  if (groupName === PROXY_GROUP_PRE_CUSTOM_KEY) {
    return 'pre'
  }

  if (groupName === PROXY_GROUP_POST_CUSTOM_KEY) {
    return 'post'
  }

  return null
}

const normalizeProxyGroupCustomMode = (value) => {
  return value === 'pre' || value === 'post' || value === 'all' ? value : null
}

const isProxyGroupCustomDirectRule = (normalizedType) => {
  return Boolean(
    normalizedType &&
    normalizedType !== 'RULE-SET' &&
    normalizedType !== 'MATCH' &&
    normalizedType !== 'FINAL',
  )
}

const expandProxyGroupRuleEntries = (groupName, rules, options = {}) => {
  const customGroupMode =
    normalizeProxyGroupCustomMode(options.customGroupMode) ||
    (options.customGroup === true ? 'all' : null) ||
    getProxyGroupCustomModeFromGroupName(groupName)
  const customGroup = customGroupMode !== null
  const relevantRules = []
  const sortedRules = [...rules]
    .filter((rule) => isRuleEnabled(rule))
    .sort((prev, next) => (prev?.index || 0) - (next?.index || 0))
  let hasSeenRuleSet = false

  sortedRules.forEach((rule) => {
    const normalizedType = normalizeRuleTypeName(rule?.type)

    if (customGroup) {
      if (normalizedType === 'RULE-SET') {
        hasSeenRuleSet = true
        return
      }

      if (!isProxyGroupCustomDirectRule(normalizedType)) {
        return
      }

      if (customGroupMode === 'all') {
        relevantRules.push(rule)
        return
      }

      const ruleMode = hasSeenRuleSet ? 'post' : 'pre'

      if (ruleMode === customGroupMode) {
        relevantRules.push(rule)
      }

      return
    }

    if (rule?.proxy === groupName) {
      relevantRules.push(rule)
    }
  })
  const entries = []
  const seenEntries = new Set()
  const missingProviders = new Set()

  const pushEntry = (entry) => {
    if (!entry) {
      return
    }

    const key = [entry.type, entry.content, entry.params, entry.raw].join('::')

    if (seenEntries.has(key)) {
      return
    }

    seenEntries.add(key)
    entries.push(entry)
  }

  for (const rule of relevantRules) {
    const normalizedType = normalizeRuleTypeName(rule?.type)

    if (normalizedType === 'RULE-SET') {
      const providerName = String(rule?.payload || '').trim()
      const cachedProvider = getCachedRuleProviderByNameStatement.get(providerName)

      if (!cachedProvider) {
        missingProviders.add(providerName)
        continue
      }

      parseRuleEntriesFromBody(cachedProvider.body, providerName).forEach(pushEntry)
      continue
    }

    pushEntry(parseDirectControllerRuleEntry(rule))
  }

  return {
    groupName,
    customGroup,
    customGroupMode,
    totalRules: relevantRules.length,
    items: entries,
    missingProviders: Array.from(missingProviders),
  }
}

const PROXY_GROUP_RULE_PENETRATION_TAB_SET = new Set(['all', 'domain', 'ip', 'port'])
const PROXY_GROUP_RULE_PENETRATION_SORT_KEY_SET = new Set(['type', 'content', 'params', 'raw'])
const PROXY_GROUP_RULE_PENETRATION_CACHE_VERSION = 3
const RULE_TYPE_DISPLAY_NAME_MAP = new Map([
  ['DOMAIN', '域名'],
  ['DOMAIN-SUFFIX', '域名后缀'],
  ['DOMAIN-KEYWORD', '关键字'],
  ['IP-CIDR', '目标IP'],
  ['IP-CIDR6', '目标IP'],
  ['SRC-IP', '源IP'],
  ['SRC-IP-CIDR', '源IP'],
  ['SRC-IP-CIDR6', '源IP'],
  ['DST-PORT', '目标端口'],
  ['SRC-PORT', '源端口'],
  ['IN-PORT', '入站端口'],
  ['GEOIP', '目标IP'],
  ['MATCH', '匹配'],
  ['FINAL', '最终'],
])

const pruneProxyGroupRulePenetrationCache = () => {
  const now = Date.now()

  for (const [cacheKey, entry] of proxyGroupRulePenetrationCache.entries()) {
    if (now - entry.lastAccessAt <= PROXY_GROUP_RULE_PENETRATION_CACHE_TTL_MS) {
      continue
    }

    proxyGroupRulePenetrationCache.delete(cacheKey)
    proxyGroupRulePenetrationCacheBySignature.delete(entry.signature)
  }

  if (proxyGroupRulePenetrationCache.size <= PROXY_GROUP_RULE_PENETRATION_CACHE_LIMIT) {
    return
  }

  const staleEntries = [...proxyGroupRulePenetrationCache.entries()].sort(
    (left, right) => left[1].lastAccessAt - right[1].lastAccessAt,
  )

  while (
    staleEntries.length > 0 &&
    proxyGroupRulePenetrationCache.size > PROXY_GROUP_RULE_PENETRATION_CACHE_LIMIT
  ) {
    const [cacheKey, entry] = staleEntries.shift()
    proxyGroupRulePenetrationCache.delete(cacheKey)
    proxyGroupRulePenetrationCacheBySignature.delete(entry.signature)
  }
}

const buildProxyGroupRulePenetrationSignature = (groupName, rules, options = {}) => {
  const customGroupMode =
    normalizeProxyGroupCustomMode(options.customGroupMode) ||
    (options.customGroup === true ? 'all' : null)

  return createHash('sha1')
    .update(
      JSON.stringify({
        version: PROXY_GROUP_RULE_PENETRATION_CACHE_VERSION,
        groupName,
        customGroup: options.customGroup === true,
        customGroupMode,
        rules,
      }),
    )
    .digest('hex')
}

const getProxyGroupRulePenetrationDisplayType = (type) => {
  return RULE_TYPE_DISPLAY_NAME_MAP.get(type) || type
}

const buildRulePenetrationCounts = (items) => {
  const counts = {
    all: items.length,
    domain: 0,
    ip: 0,
    port: 0,
  }

  items.forEach((entry) => {
    if (entry.family === 'domain') {
      counts.domain += 1
    } else if (entry.family === 'ip') {
      counts.ip += 1
    } else if (entry.family === 'port') {
      counts.port += 1
    }
  })

  return counts
}

const normalizeProxyGroupRulePenetrationTab = (value) => {
  return PROXY_GROUP_RULE_PENETRATION_TAB_SET.has(value) ? value : 'all'
}

const normalizeProxyGroupRulePenetrationSortKey = (value) => {
  return PROXY_GROUP_RULE_PENETRATION_SORT_KEY_SET.has(value) ? value : null
}

const normalizeProxyGroupRulePenetrationSortDirection = (value) => {
  return value === 'desc' ? 'desc' : 'asc'
}

const normalizePositiveInteger = (value, defaultValue, maxValue) => {
  const parsed = Number.parseInt(String(value || ''), 10)

  if (!Number.isFinite(parsed) || parsed <= 0) {
    return defaultValue
  }

  return Math.min(parsed, maxValue)
}

const getProxyGroupRulePenetrationCacheEntry = ({
  groupName,
  cacheKey,
  rules,
  customGroup = false,
  customGroupMode = null,
}) => {
  pruneProxyGroupRulePenetrationCache()
  const normalizedCustomGroupMode =
    normalizeProxyGroupCustomMode(customGroupMode) || (customGroup === true ? 'all' : null)

  if (cacheKey) {
    const cachedEntry = proxyGroupRulePenetrationCache.get(cacheKey)

    if (
      !cachedEntry ||
      cachedEntry.groupName !== groupName ||
      cachedEntry.customGroup !== customGroup ||
      cachedEntry.customGroupMode !== normalizedCustomGroupMode
    ) {
      const error = new Error('cache expired')
      error.code = 'CACHE_EXPIRED'
      throw error
    }

    cachedEntry.lastAccessAt = Date.now()
    return cachedEntry
  }

  const signature = buildProxyGroupRulePenetrationSignature(groupName, rules, {
    customGroup,
    customGroupMode: normalizedCustomGroupMode,
  })
  const reusedCacheKey = proxyGroupRulePenetrationCacheBySignature.get(signature)

  if (reusedCacheKey) {
    const reusedEntry = proxyGroupRulePenetrationCache.get(reusedCacheKey)

    if (reusedEntry) {
      reusedEntry.lastAccessAt = Date.now()
      return reusedEntry
    }

    proxyGroupRulePenetrationCacheBySignature.delete(signature)
  }

  const expanded = expandProxyGroupRuleEntries(groupName, rules, {
    customGroup,
    customGroupMode: normalizedCustomGroupMode,
  })
  const nextCacheKey = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  const createdEntry = {
    cacheKey: nextCacheKey,
    signature,
    groupName,
    customGroup,
    customGroupMode: expanded.customGroupMode,
    totalRules: expanded.totalRules,
    items: expanded.items,
    missingProviders: expanded.missingProviders,
    createdAt: Date.now(),
    lastAccessAt: Date.now(),
  }

  proxyGroupRulePenetrationCache.set(nextCacheKey, createdEntry)
  proxyGroupRulePenetrationCacheBySignature.set(signature, nextCacheKey)
  pruneProxyGroupRulePenetrationCache()

  return createdEntry
}

const matchesProxyGroupRulePenetrationSearch = (entry, search) => {
  if (!search) {
    return true
  }

  const normalizedSearch = search.toLowerCase()

  return [
    entry.type,
    getProxyGroupRulePenetrationDisplayType(entry.type),
    entry.content,
    entry.params,
    entry.raw,
  ].some((value) =>
    String(value || '')
      .toLowerCase()
      .includes(normalizedSearch),
  )
}

const sortProxyGroupRulePenetrationEntries = (items, sortKey, sortDirection) => {
  if (!sortKey) {
    return items
  }

  const direction = sortDirection === 'desc' ? -1 : 1

  return [...items].sort((left, right) => {
    const leftValue =
      sortKey === 'type' ? getProxyGroupRulePenetrationDisplayType(left.type) : left[sortKey]
    const rightValue =
      sortKey === 'type' ? getProxyGroupRulePenetrationDisplayType(right.type) : right[sortKey]

    return (
      String(leftValue || '').localeCompare(String(rightValue || ''), 'zh-Hans-CN', {
        numeric: true,
        sensitivity: 'base',
      }) * direction
    )
  })
}

const normalizeLookupInput = (value) => {
  const input = value.trim()

  if (!input) {
    return null
  }

  let candidate = input

  try {
    candidate = new URL(input.includes('://') ? input : `https://${input}`).hostname || input
  } catch {
    candidate = input.split('/')[0]
  }

  const trimmedCandidate = candidate.trim()
  const ipVersion = isIP(trimmedCandidate)

  if (ipVersion) {
    const parsedIp = parseIpAddress(trimmedCandidate)

    if (!parsedIp) {
      return null
    }

    return {
      raw: input,
      type: 'ip',
      value: trimmedCandidate.toLowerCase(),
      parsedIp,
    }
  }

  const normalizedDomainValue = normalizeDomain(trimmedCandidate)

  if (/^[a-z0-9.-]+$/i.test(normalizedDomainValue) && normalizedDomainValue.includes('.')) {
    return {
      raw: input,
      type: 'domain',
      value: normalizedDomainValue,
    }
  }

  const keyword = normalizeKeyword(input)

  if (!keyword) {
    return null
  }

  return {
    raw: input,
    type: 'keyword',
    value: keyword,
  }
}

const mergeLookupMatches = (matchesList) => {
  const seen = new Set()
  const merged = []

  matchesList.flat().forEach((match) => {
    const key = `${match.line}:${match.mode}:${match.value}:${match.raw}`

    if (seen.has(key)) {
      return
    }

    seen.add(key)
    merged.push(match)
  })

  return merged.sort((left, right) => {
    if (left.line !== right.line) {
      return left.line - right.line
    }

    return left.raw.localeCompare(right.raw, 'zh-Hans-CN', {
      numeric: true,
      sensitivity: 'base',
    })
  })
}

const findMatchesInTextRulesByLookups = async (lookups, body) => {
  return mergeLookupMatches(lookups.map((lookup) => findMatchesInTextRules(lookup, body)))
}
const countRulesInBody = (body) => {
  if (!body || !body.trim()) {
    return 0
  }

  return body.split(/\r?\n/).filter((line) => {
    const trimmedLine = line.trim()

    return (
      trimmedLine &&
      !trimmedLine.startsWith('#') &&
      !trimmedLine.startsWith('//') &&
      !/^payload\s*:/i.test(trimmedLine)
    )
  }).length
}

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
])

const getProxyTarget = (req) => {
  const rawBase = req.header('x-zashboard-target-base')

  if (!rawBase) {
    throw new Error('Missing x-zashboard-target-base header')
  }

  const target = new URL(rawBase)

  if (!['http:', 'https:'].includes(target.protocol)) {
    throw new Error('Only http and https controller targets are supported')
  }

  return {
    base: target,
    secret: req.header('x-zashboard-target-secret') || '',
  }
}

const buildUpstreamUrl = (req, targetBase) => {
  const suffix = req.originalUrl.slice('/api/controller'.length) || '/'
  const normalizedBase = targetBase.toString().replace(/\/$/, '')

  return new URL(`${normalizedBase}${suffix.startsWith('/') ? suffix : `/${suffix}`}`)
}

const buildProxyPath = (basePath, suffix) => {
  const normalizedBasePath = (basePath || '').replace(/\/+$/, '')
  const normalizedSuffix = (suffix || '').replace(/^\/+/, '')

  if (!normalizedBasePath && !normalizedSuffix) {
    return '/'
  }

  if (!normalizedBasePath) {
    return `/${normalizedSuffix}`
  }

  if (!normalizedSuffix) {
    return normalizedBasePath || '/'
  }

  return `${normalizedBasePath}/${normalizedSuffix}`
}

const getControllerBaseUrl = (backend) => {
  const baseUrl = new URL(`${backend.protocol}://${backend.host}:${backend.port}`)

  if (backend.secondaryPath) {
    baseUrl.pathname = buildProxyPath(baseUrl.pathname, backend.secondaryPath)
  }

  return baseUrl
}

const createControllerRequestUrl = (backend, suffix) => {
  const baseUrl = getControllerBaseUrl(backend)
  const normalizedBase = baseUrl.toString().replace(/\/$/, '')

  return new URL(`${normalizedBase}${suffix.startsWith('/') ? suffix : `/${suffix}`}`)
}

const controllerFetch = async (backend, suffix, options = {}) => {
  const headers = new Headers(options.headers || {})

  if (backend.password) {
    headers.set('Authorization', `Bearer ${backend.password}`)
  } else {
    headers.delete('Authorization')
  }

  const response = await fetch(createControllerRequestUrl(backend, suffix), {
    ...options,
    headers,
    signal: options.signal ?? activeRuleRefreshController?.signal,
  })

  if (!response.ok) {
    const message = await response.text().catch(() => '')
    throw new Error(message || `Controller request failed: ${response.status}`)
  }

  return response
}

const fetchControllerRuleProviders = async (backend) => {
  const response = await controllerFetch(backend, '/providers/rules', {
    headers: {
      Accept: 'application/json',
    },
  })

  const data = await response.json()
  return Object.values(data?.providers || {})
}

const fetchControllerRules = async (backend) => {
  const response = await controllerFetch(backend, '/rules', {
    headers: {
      Accept: 'application/json',
    },
  })

  const data = await response.json()
  return Array.isArray(data?.rules) ? data.rules : []
}

const getReferencedProviderNamesFromControllerRules = (rules) => {
  const seen = new Set()
  const names = []

  rules.forEach((rule) => {
    if (!isRuleEnabled(rule) || normalizeRuleTypeName(rule?.type) !== 'RULE-SET') {
      return
    }

    const providerName = String(rule?.payload || '').trim()

    if (!providerName || seen.has(providerName)) {
      return
    }

    seen.add(providerName)
    names.push(providerName)
  })

  return names
}

const proxyControllerRequest = async (req, res) => {
  try {
    const { base, secret } = getProxyTarget(req)
    const upstreamUrl = buildUpstreamUrl(req, base)
    const headers = new Headers()

    Object.entries(req.headers).forEach(([key, value]) => {
      const normalizedKey = key.toLowerCase()

      if (
        HOP_BY_HOP_HEADERS.has(normalizedKey) ||
        normalizedKey.startsWith('x-zashboard-target-')
      ) {
        return
      }

      if (Array.isArray(value)) {
        headers.set(key, value.join(', '))
        return
      }

      if (typeof value === 'string') {
        headers.set(key, value)
      }
    })

    if (secret) {
      headers.set('Authorization', `Bearer ${secret}`)
    } else {
      headers.delete('Authorization')
    }

    const response = await fetch(upstreamUrl, {
      method: req.method,
      headers,
      body:
        req.method === 'GET' || req.method === 'HEAD'
          ? undefined
          : Buffer.isBuffer(req.body) && req.body.length
            ? req.body
            : undefined,
    })

    res.status(response.status)

    response.headers.forEach((value, key) => {
      if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
        res.setHeader(key, value)
      }
    })

    const body = Buffer.from(await response.arrayBuffer())
    res.send(body)
  } catch (error) {
    res.status(502).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
}

const getWebSocketProxyTarget = (requestUrl) => {
  const targetBaseRaw = requestUrl.searchParams.get('targetBase')

  if (!targetBaseRaw) {
    throw new Error('Missing targetBase query parameter')
  }

  const targetBase = new URL(targetBaseRaw)

  if (!['http:', 'https:'].includes(targetBase.protocol)) {
    throw new Error('Only http and https controller targets are supported')
  }

  return {
    base: targetBase,
    secret: requestUrl.searchParams.get('secret') || '',
  }
}

const buildUpstreamWebSocketUrl = (requestUrl, targetBase, secret) => {
  const suffix = requestUrl.pathname.slice('/api/controller-ws'.length) || '/'
  const upstreamUrl = new URL(targetBase.toString())

  upstreamUrl.protocol = targetBase.protocol === 'https:' ? 'wss:' : 'ws:'
  upstreamUrl.pathname = buildProxyPath(upstreamUrl.pathname, suffix)
  upstreamUrl.search = ''

  requestUrl.searchParams.forEach((value, key) => {
    if (key !== 'targetBase' && key !== 'secret') {
      upstreamUrl.searchParams.append(key, value)
    }
  })

  if (secret) {
    upstreamUrl.searchParams.set('token', secret)
  }

  return upstreamUrl
}

const normalizeCloseCode = (code, fallback = 1000) => {
  if (!Number.isInteger(code)) {
    return fallback
  }

  if (code >= 3000 && code <= 4999) {
    return code
  }

  if (code >= 1000 && code <= 1014 && ![1004, 1005, 1006].includes(code)) {
    return code
  }

  return fallback
}

const closeSocket = (socket, code = 1000, reason = '') => {
  if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
    socket.close(normalizeCloseCode(code), reason)
  }
}

const closeSocketPair = (left, right, code = 1011, reason = '') => {
  closeSocket(left, code, reason)
  closeSocket(right, code, reason)
}

const relayControllerWebSocket = (clientSocket, request) => {
  let upstreamSocket

  try {
    const requestUrl = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`)
    const { base, secret } = getWebSocketProxyTarget(requestUrl)
    const upstreamUrl = buildUpstreamWebSocketUrl(requestUrl, base, secret)

    upstreamSocket = new WebSocket(upstreamUrl)

    const closeBoth = (code, reason) => {
      closeSocketPair(clientSocket, upstreamSocket, code, reason)
    }

    clientSocket.on('message', (data, isBinary) => {
      if (upstreamSocket.readyState === WebSocket.OPEN) {
        upstreamSocket.send(data, { binary: isBinary })
      }
    })

    clientSocket.on('close', (code, reason) => {
      closeSocket(upstreamSocket, code, reason?.toString())
    })

    clientSocket.on('error', () => {
      closeBoth(1011, 'Client websocket error')
    })

    upstreamSocket.on('message', (data, isBinary) => {
      if (clientSocket.readyState === WebSocket.OPEN) {
        clientSocket.send(data, { binary: isBinary })
      }
    })

    upstreamSocket.on('close', (code, reason) => {
      closeSocket(clientSocket, code, reason?.toString())
    })

    upstreamSocket.on('error', () => {
      closeBoth(1011, 'Upstream websocket error')
    })
  } catch (error) {
    closeSocket(clientSocket, 1011, error instanceof Error ? error.message : String(error))

    if (upstreamSocket) {
      closeSocket(upstreamSocket, 1011)
    }
  }
}

const isDomainMatch = (domain, ruleValue, mode) => {
  const normalizedDomain = normalizeDomain(domain)
  const normalizedRule = normalizeDomain(ruleValue)

  if (!normalizedDomain || !normalizedRule) {
    return false
  }

  if (mode === 'domain') {
    return normalizedDomain === normalizedRule
  }

  if (mode === 'suffix') {
    return normalizedDomain === normalizedRule || normalizedDomain.endsWith(`.${normalizedRule}`)
  }

  if (mode === 'keyword') {
    return normalizedDomain.includes(normalizedRule)
  }

  return false
}

const isDomainSearchMatch = (domain, ruleValue, mode) => {
  const normalizedDomain = normalizeDomain(domain)
  const normalizedRule = normalizeDomain(ruleValue)

  if (!normalizedDomain || !normalizedRule) {
    return false
  }

  if (isDomainMatch(normalizedDomain, normalizedRule, mode)) {
    return true
  }

  if (mode === 'domain' || mode === 'suffix') {
    return normalizedRule === normalizedDomain || normalizedRule.endsWith(`.${normalizedDomain}`)
  }

  return false
}

const isKeywordMatch = (keyword, ruleValue) => {
  const normalizedRule = normalizeDomain(ruleValue)

  return Boolean(keyword && normalizedRule && normalizedRule.includes(keyword))
}

const getKeywordMatchScore = (keyword, match) => {
  const normalizedRule = normalizeDomain(match.value)

  if (!keyword || !normalizedRule) {
    return Number.MIN_SAFE_INTEGER
  }

  const index = normalizedRule.indexOf(keyword)

  if (index === -1) {
    return Number.MIN_SAFE_INTEGER
  }

  const previousChar = normalizedRule[index - 1] || ''
  const nextChar = normalizedRule[index + keyword.length] || ''
  let score = 0

  if (normalizedRule === keyword) {
    score += 400
  }

  if (index === 0) {
    score += 120
  } else if (/[-_.]/.test(previousChar)) {
    score += 40
  }

  if (!nextChar) {
    score += 160
  } else if (nextChar === '.') {
    score += 140
  } else if (nextChar === '-') {
    score += 100
  } else if (nextChar === '_') {
    score += 80
  } else {
    score -= 10
  }

  if (match.mode === 'domain') {
    score += 30
  } else if (match.mode === 'suffix') {
    score += 20
  } else if (match.mode === 'keyword') {
    score += 10
  }

  score -= index * 8
  score -= normalizedRule.length

  return score
}

const sortRuleMatchesByLookup = (lookup, matches) => {
  if (lookup.type !== 'keyword') {
    return matches
  }

  return [...matches].sort((left, right) => {
    const scoreDelta =
      getKeywordMatchScore(lookup.value, right) - getKeywordMatchScore(lookup.value, left)

    if (scoreDelta !== 0) {
      return scoreDelta
    }

    return left.line - right.line
  })
}

const parseIPv4Address = (value) => {
  const parts = value.split('.')

  if (parts.length !== 4) {
    return null
  }

  let result = 0n

  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return null
    }

    const octet = Number(part)

    if (octet < 0 || octet > 255) {
      return null
    }

    result = (result << 8n) + BigInt(octet)
  }

  return {
    version: 4,
    bits: 32,
    value: result,
  }
}

const parseIPv6Address = (value) => {
  let normalized = value.toLowerCase()

  if (normalized.includes('.')) {
    const lastColonIndex = normalized.lastIndexOf(':')

    if (lastColonIndex === -1) {
      return null
    }

    const ipv4Address = parseIPv4Address(normalized.slice(lastColonIndex + 1))

    if (!ipv4Address) {
      return null
    }

    normalized = `${normalized.slice(0, lastColonIndex)}:${Number(
      (ipv4Address.value >> 16n) & 0xffffn,
    ).toString(16)}:${Number(ipv4Address.value & 0xffffn).toString(16)}`
  }

  const doubleColonIndex = normalized.indexOf('::')

  if (doubleColonIndex !== normalized.lastIndexOf('::')) {
    return null
  }

  const headSegments =
    doubleColonIndex === -1
      ? normalized.split(':')
      : normalized.slice(0, doubleColonIndex).split(':').filter(Boolean)
  const tailSegments =
    doubleColonIndex === -1
      ? []
      : normalized
          .slice(doubleColonIndex + 2)
          .split(':')
          .filter(Boolean)

  if (doubleColonIndex === -1 && headSegments.length !== 8) {
    return null
  }

  if (headSegments.length + tailSegments.length > 8) {
    return null
  }

  const segments =
    doubleColonIndex === -1
      ? headSegments
      : [
          ...headSegments,
          ...Array.from({ length: 8 - headSegments.length - tailSegments.length }, () => '0'),
          ...tailSegments,
        ]

  if (segments.length !== 8) {
    return null
  }

  let result = 0n

  for (const segment of segments) {
    if (!/^[0-9a-f]{1,4}$/i.test(segment)) {
      return null
    }

    result = (result << 16n) + BigInt(`0x${segment}`)
  }

  return {
    version: 6,
    bits: 128,
    value: result,
  }
}

const parseIpAddress = (value) => {
  const ipVersion = isIP(value)

  if (ipVersion === 4) {
    return parseIPv4Address(value)
  }

  if (ipVersion === 6) {
    return parseIPv6Address(value)
  }

  return null
}

const parseIpCidr = (value) => {
  const trimmedValue = value.trim()

  if (!trimmedValue) {
    return null
  }

  const parts = trimmedValue.split('/')

  if (parts.length > 2) {
    return null
  }

  const parsedAddress = parseIpAddress(parts[0])

  if (!parsedAddress) {
    return null
  }

  const prefix = parts.length === 2 ? Number.parseInt(parts[1], 10) : parsedAddress.bits

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > parsedAddress.bits) {
    return null
  }

  const suffixBits = BigInt(parsedAddress.bits - prefix)
  const network =
    suffixBits === 0n ? parsedAddress.value : (parsedAddress.value >> suffixBits) << suffixBits
  const size = 1n << suffixBits

  return {
    version: parsedAddress.version,
    prefix,
    start: network,
    end: network + size - 1n,
  }
}

const isIpInCidr = (parsedIp, ruleValue) => {
  const parsedRule = parseIpCidr(ruleValue)

  if (!parsedRule || parsedRule.version !== parsedIp.version) {
    return false
  }

  return parsedIp.value >= parsedRule.start && parsedIp.value <= parsedRule.end
}

const findMatchesInTextRules = (lookup, body) => {
  const matches = []
  const lines = body.split(/\r?\n/)

  lines.forEach((rawLine, index) => {
    const line = rawLine.trim()

    if (!line || line.startsWith('#') || line.startsWith('//') || /^payload\s*:/i.test(line)) {
      return
    }

    const normalizedLine = line.startsWith('- ') ? line.slice(2).trim() : line

    if (!normalizedLine) {
      return
    }

    if (/^(domain|suffix|keyword|ip-cidr|ip-cidr6):/i.test(normalizedLine)) {
      const [, key, value] = normalizedLine.match(/^([^:]+):\s*(.+)$/) || []

      if (!key || !value) {
        return
      }

      const normalizedKey = key.toLowerCase()

      if (lookup.type === 'ip') {
        const mode = normalizedKey.includes('6') ? 'ip-cidr6' : 'ip-cidr'

        if (normalizedKey.includes('ip') && isIpInCidr(lookup.parsedIp, value)) {
          matches.push({ line: index + 1, value, mode, raw: normalizedLine })
        }

        return
      }

      const mode = normalizedKey.includes('suffix')
        ? 'suffix'
        : normalizedKey.includes('keyword')
          ? 'keyword'
          : 'domain'

      const isMatched =
        lookup.type === 'domain'
          ? isDomainSearchMatch(lookup.value, value, mode)
          : isKeywordMatch(lookup.value, value)

      if (isMatched) {
        matches.push({ line: index + 1, value, mode, raw: normalizedLine })
      }

      return
    }

    if (lookup.type !== 'ip' && normalizedLine.startsWith('+.')) {
      const value = normalizedLine.slice(2)
      const isMatched =
        lookup.type === 'domain'
          ? isDomainSearchMatch(lookup.value, value, 'suffix')
          : isKeywordMatch(lookup.value, value)

      if (isMatched) {
        matches.push({ line: index + 1, value, mode: 'suffix', raw: normalizedLine })
      }

      return
    }

    const parts = normalizedLine.split(',').map((part) => part.trim())
    const ruleType = parts[0]?.toUpperCase()
    const value = parts[1] || parts[0]

    if (lookup.type === 'ip') {
      const supportsIpMatch =
        ['IP-CIDR', 'IP-CIDR6', 'SRC-IP', 'SRC-IP-CIDR', 'SRC-IP-CIDR6'].includes(ruleType) ||
        (!normalizedLine.includes(',') && Boolean(parseIpCidr(normalizedLine)))

      if (supportsIpMatch && isIpInCidr(lookup.parsedIp, value)) {
        matches.push({
          line: index + 1,
          value,
          mode: ruleType === 'IP-CIDR6' || ruleType === 'SRC-IP-CIDR6' ? 'ip-cidr6' : 'ip-cidr',
          raw: normalizedLine,
        })
      }

      return
    }

    const supportsDomainMatch =
      ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].includes(ruleType) ||
      (!ruleType.includes('IP') && !ruleType.includes('PROCESS') && !normalizedLine.includes(','))

    if (!supportsDomainMatch) {
      return
    }

    const mode =
      ruleType === 'DOMAIN-SUFFIX' ? 'suffix' : ruleType === 'DOMAIN-KEYWORD' ? 'keyword' : 'domain'
    const isMatched =
      lookup.type === 'domain'
        ? isDomainSearchMatch(lookup.value, value, mode)
        : isKeywordMatch(lookup.value, value)

    if (isMatched) {
      matches.push({ line: index + 1, value, mode, raw: normalizedLine })
    }
  })

  return matches
}

const convertMrsToText = async (provider, buffer) => {
  if (!fs.existsSync(mihomoBinaryPath)) {
    throw new Error(`Mihomo binary not found: ${mihomoBinaryPath}`)
  }

  const tempName = `${Date.now()}-${Math.random().toString(36).slice(2)}`
  const sourcePath = path.join(ruleSearchTempDir, `${tempName}.mrs`)
  const targetPath = path.join(ruleSearchTempDir, `${tempName}.txt`)
  const behavior = provider.kind === 'mrs-ip' ? 'ipcidr' : 'domain'

  fs.writeFileSync(sourcePath, buffer)

  try {
    await execFileAsync(
      mihomoBinaryPath,
      ['convert-ruleset', behavior, 'mrs', sourcePath, targetPath],
      {
        windowsHide: true,
      },
    )

    return fs.readFileSync(targetPath, 'utf8')
  } finally {
    if (fs.existsSync(sourcePath)) fs.unlinkSync(sourcePath)
    if (fs.existsSync(targetPath)) fs.unlinkSync(targetPath)
  }
}

const fetchProviderBody = async (provider) => {
  const response = await fetch(provider.url, {
    signal: activeRuleProviderUpdateController?.signal,
  })

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`)
  }

  return provider.kind === 'mrs-domain' || provider.kind === 'mrs-ip'
    ? await convertMrsToText(provider, Buffer.from(await response.arrayBuffer()))
    : await response.text()
}

const saveProviderToCache = (provider, body) => {
  upsertRuleProviderCacheStatement.run(
    provider.name,
    provider.behavior,
    provider.format,
    provider.kind,
    provider.url,
    provider.interval,
    body,
  )
}

const getRuleProviderCacheRuleCount = () => {
  const row = getRuleProviderCacheTotalCountStatement.get()

  return Number(row?.total || 0)
}

const getRuleProviderCacheProviderCounts = () => {
  return Object.fromEntries(
    getCachedRuleProviderStatement
      .all()
      .map((provider) => [provider.name, countRulesInBody(provider.body)]),
  )
}

const buildRuleProviderSourceMetadata = (providers, extra = {}) => ({
  providerUrls: Object.fromEntries(
    providers
      .filter((provider) => provider.name && provider.url)
      .map((provider) => [provider.name, provider.url]),
  ),
  providerOrder: providers.map((provider) => String(provider.name || '').trim()).filter(Boolean),
  plugin: extra.plugin || '',
  configPath: extra.configPath || '',
  updatedAt: Date.now(),
})

const normalizeRuleProviderSourceMetadata = (metadata = {}) => {
  const providerUrls =
    metadata?.providerUrls &&
    typeof metadata.providerUrls === 'object' &&
    !Array.isArray(metadata.providerUrls)
      ? Object.fromEntries(
          Object.entries(metadata.providerUrls)
            .map(([name, url]) => [String(name || '').trim(), normalizeRuleProviderUrl(url)])
            .filter(([name, url]) => name && url),
        )
      : {}
  const providerOrder = Array.isArray(metadata?.providerOrder)
    ? [...new Set(metadata.providerOrder.map((name) => String(name || '').trim()).filter(Boolean))]
    : []

  return {
    providerUrls,
    providerOrder,
    plugin: typeof metadata?.plugin === 'string' ? metadata.plugin : '',
    configPath: typeof metadata?.configPath === 'string' ? metadata.configPath : '',
    updatedAt: Number(metadata?.updatedAt || 0) || 0,
  }
}

const hasRuleProviderSourceMetadata = (metadata) =>
  Object.keys(metadata.providerUrls || {}).length > 0 || (metadata.providerOrder || []).length > 0

const saveRuleProviderSourceMetadata = (providers, extra = {}) => {
  const metadata = buildRuleProviderSourceMetadata(providers, extra)

  upsertStorageValueStatement.run(RULE_PROVIDER_SOURCE_METADATA_KEY, JSON.stringify(metadata))

  return normalizeRuleProviderSourceMetadata(metadata)
}

const getCachedRuleProviderSourceMetadata = () => {
  const row = getStorageValueStatement.get(RULE_PROVIDER_SOURCE_METADATA_KEY)
  const storedMetadata = normalizeRuleProviderSourceMetadata(parseStoredJson(row?.value, {}))

  if (hasRuleProviderSourceMetadata(storedMetadata)) {
    return storedMetadata
  }

  const cachedProviders = getCachedRuleProviderStatement.all()

  return normalizeRuleProviderSourceMetadata({
    providerUrls: Object.fromEntries(
      cachedProviders
        .filter((provider) => provider.name && provider.source_url)
        .map((provider) => [provider.name, provider.source_url]),
    ),
    providerOrder: cachedProviders.map((provider) => provider.name),
  })
}

const getRuleProviderSourceMetadata = async (options = {}) => {
  const cachedMetadata = getCachedRuleProviderSourceMetadata()

  if (hasRuleProviderSourceMetadata(cachedMetadata) || options.allowLive === false) {
    return cachedMetadata
  }

  try {
    const snapshot = await getOpenWrtRuleSourceSnapshot()

    if (!snapshot) {
      return cachedMetadata
    }

    return saveRuleProviderSourceMetadata(snapshot.providers, {
      plugin: snapshot.plugin,
      configPath: snapshot.configPath,
    })
  } catch {
    return cachedMetadata
  }
}

const replaceRuleProviderCache = (items, options = {}) => {
  const force = options.force ?? false

  db.exec('BEGIN')

  try {
    if (force) {
      clearRuleProviderCacheStatement.run()
    }

    for (const item of items) {
      saveProviderToCache(item.provider, item.body)
    }

    db.exec('COMMIT')
  } catch (error) {
    db.exec('ROLLBACK')
    throw error
  }
}

const seedRuleProviderCacheForTesting = (items) => {
  replaceRuleProviderCache(
    items.map((item) => ({
      provider: {
        name: item.name,
        behavior: item.behavior,
        format: item.format,
        kind: item.kind || getRuleProviderKind(item.url, item.format, item.behavior),
        url: item.url,
        interval: item.interval || 0,
      },
      body: item.body,
    })),
    {
      force: true,
    },
  )
}

const isCacheExpired = (updatedAt, intervalSeconds) => {
  if (!intervalSeconds || intervalSeconds <= 0) {
    return false
  }

  const updatedTime = new Date(updatedAt).getTime()

  if (Number.isNaN(updatedTime)) {
    return true
  }

  return Date.now() - updatedTime >= intervalSeconds * 1000
}

const waitForProgressFrame = async (durationMs) => {
  if (!durationMs || durationMs <= 0) {
    return
  }

  await new Promise((resolve) => {
    const timer = setTimeout(resolve, durationMs)

    if (typeof timer?.unref === 'function') {
      timer.unref()
    }
  })
}

const animateRuleCountProgress = async ({ startCount, endCount, signal, onProgress }) => {
  const safeStartCount = Number.isFinite(startCount) ? startCount : 0
  const safeEndCount = Number.isFinite(endCount) ? endCount : 0

  if (safeStartCount === safeEndCount) {
    onProgress(safeEndCount)
    return
  }

  const delta = safeEndCount - safeStartCount
  const steps = Math.min(20, Math.max(Math.abs(delta), 2))
  const totalDurationMs = Math.min(1600, Math.max(900, steps * 80))
  const frameDurationMs = Math.max(60, Math.round(totalDurationMs / steps))

  for (let step = 1; step <= steps; step++) {
    if (signal?.aborted) {
      return
    }

    onProgress(safeStartCount + Math.round((delta * step) / steps))

    if (step < steps) {
      await waitForProgressFrame(frameDurationMs)
    }
  }
}

const updateRuleProviderCache = async (options = {}) => {
  if (activeRuleProviderUpdatePromise) {
    return await activeRuleProviderUpdatePromise
  }

  activeRuleProviderUpdatePromise = (async () => {
    const force = options.force ?? true
    const providerNames =
      Array.isArray(options.providerNames) && options.providerNames.length > 0
        ? [
            ...new Set(
              options.providerNames.map((name) => String(name || '').trim()).filter(Boolean),
            ),
          ]
        : null
    const ruleSourceSnapshot = options.ruleSourceSnapshot || (await assertRuleSourceReadyForSync())
    const runtimeProviderEntries = ruleSourceSnapshot.providers
    const sourceMetadata = saveRuleProviderSourceMetadata(runtimeProviderEntries, {
      plugin: ruleSourceSnapshot.plugin,
      configPath: ruleSourceSnapshot.configPath,
    })

    const ruleSourceConfigSync = {
      changed: false,
      updatedProviders: runtimeProviderEntries.length,
      path: ruleSourceSnapshot.configPath,
      skipped: false,
      error: '',
      plugin: ruleSourceSnapshot.plugin,
    }

    const providers = runtimeProviderEntries
      .map((provider) => ({
        ...provider,
        kind: getRuleProviderKind(provider.url, provider.format, provider.behavior),
      }))
      .filter((provider) => !providerNames || providerNames.includes(provider.name))
    const configuredProviderNameSet = new Set(providers.map((provider) => provider.name))
    const unresolvedProviderNames =
      providerNames?.filter((providerName) => !configuredProviderNameSet.has(providerName)) || []
    const cachedProviderMap = new Map(
      getCachedRuleProviderStatement.all().map((provider) => [provider.name, provider]),
    )
    const errors = unresolvedProviderNames.map((providerName) => ({
      name: providerName,
      url: '',
      message: `Rule provider source URL is not configured for "${providerName}". Check the current OpenClash/Nikki YAML read through OpenWrt SSH.`,
    }))
    let updatedCount = 0
    let progressRules = 0
    const fetchedItems = []
    const unsupportedCount = 0

    activeRuleProviderUpdateController = new AbortController()
    ruleProviderUpdateState = {
      isUpdating: true,
      totalProviders: providers.length,
      updatedProviders: 0,
      totalRules: 0,
      errors: errors.length,
      unsupportedCount,
      cancelled: false,
      completed: false,
    }

    for (const provider of providers) {
      if (activeRuleProviderUpdateController.signal.aborted) {
        break
      }

      const cachedProvider = cachedProviderMap.get(provider.name)
      const shouldRefresh =
        force ||
        !cachedProvider ||
        cachedProvider.source_url !== provider.url ||
        cachedProvider.kind !== provider.kind ||
        cachedProvider.behavior !== provider.behavior ||
        cachedProvider.format !== provider.format ||
        cachedProvider.interval_seconds !== provider.interval ||
        isCacheExpired(cachedProvider.updated_at, provider.interval)

      if (!shouldRefresh) {
        continue
      }

      try {
        const body = await fetchProviderBody(provider)

        if (activeRuleProviderUpdateController.signal.aborted) {
          break
        }

        fetchedItems.push({ provider, body })
        updatedCount++
        const nextRuleCount = countRulesInBody(body)

        if (providerNames?.length === 1) {
          await animateRuleCountProgress({
            startCount: 0,
            endCount: nextRuleCount,
            signal: activeRuleProviderUpdateController?.signal,
            onProgress: (displayCount) => {
              ruleProviderUpdateState = {
                ...ruleProviderUpdateState,
                updatedProviders: updatedCount,
                totalRules: displayCount,
              }
            },
          })

          if (activeRuleProviderUpdateController.signal.aborted) {
            break
          }

          progressRules = nextRuleCount
        } else {
          progressRules += nextRuleCount
          ruleProviderUpdateState = {
            ...ruleProviderUpdateState,
            updatedProviders: updatedCount,
            totalRules: progressRules,
          }
        }
      } catch (error) {
        if (activeRuleProviderUpdateController.signal.aborted) {
          break
        }

        errors.push({
          name: provider.name,
          url: provider.url,
          message: error instanceof Error ? error.message : String(error),
        })
        ruleProviderUpdateState = {
          ...ruleProviderUpdateState,
          errors: errors.length,
        }
      }
    }

    const cancelled = activeRuleProviderUpdateController.signal.aborted

    if (!cancelled) {
      replaceRuleProviderCache(fetchedItems, { force: force && !providerNames })
    }

    ruleProviderUpdateState = {
      ...ruleProviderUpdateState,
      isUpdating: false,
      cancelled,
      completed: true,
    }

    return {
      ok: true,
      totalProviders: providers.length,
      updatedCount,
      unsupportedCount,
      mode: force ? 'force' : 'interval',
      providerNames,
      totalRules: getRuleProviderCacheRuleCount(),
      providerCounts: getRuleProviderCacheProviderCounts(),
      providerUrls: sourceMetadata.providerUrls,
      providerOrder: sourceMetadata.providerOrder,
      progressRules,
      cancelled,
      errors,
      ruleSourceConfigSync,
    }
  })()

  try {
    return await activeRuleProviderUpdatePromise
  } finally {
    activeRuleProviderUpdatePromise = null
    activeRuleProviderUpdateController = null
  }
}

const cancelRuleProviderUpdate = () => {
  if (activeRuleProviderUpdateController && !activeRuleProviderUpdateController.signal.aborted) {
    activeRuleProviderUpdateController.abort()
    ruleProviderUpdateState = {
      ...ruleProviderUpdateState,
      isUpdating: false,
      cancelled: true,
      completed: true,
    }
    return true
  }

  return false
}

const runRuleProviderAutoRefresh = async (reason = 'interval') => {
  try {
    const result = await updateRuleProviderCache({ force: false })

    if (result.updatedCount > 0 || result.errors.length > 0) {
      console.log(
        `[rule-provider-cache] auto refresh (${reason}) finished: ${result.updatedCount}/${result.totalProviders} providers updated, ${result.totalRules} rules cached`,
      )

      if (result.errors.length > 0) {
        console.warn(
          '[rule-provider-cache] auto refresh completed with errors:',
          result.errors.map((entry) => `${entry.name}: ${entry.message}`).join('; '),
        )
      }
    }
  } catch (error) {
    console.warn(`[rule-provider-cache] auto refresh (${reason}) failed`, error)
  }
}

const startRuleProviderAutoRefresh = () => {
  if (ruleProviderAutoRefreshTimer) {
    return
  }

  ruleProviderAutoRefreshTimer = setInterval(() => {
    void runRuleProviderAutoRefresh()
  }, RULE_PROVIDER_AUTO_REFRESH_CHECK_MS)

  if (typeof ruleProviderAutoRefreshTimer.unref === 'function') {
    ruleProviderAutoRefreshTimer.unref()
  }
}

const stopRuleProviderAutoRefresh = () => {
  if (!ruleProviderAutoRefreshTimer) {
    return
  }

  clearInterval(ruleProviderAutoRefreshTimer)
  ruleProviderAutoRefreshTimer = null
}

const getRuleRefreshResponsePayload = (options = {}) => {
  const providerName = options.providerName ? String(options.providerName).trim() : ''

  return {
    refresh: ruleRefreshState,
    progress: ruleProviderUpdateState,
    totalRules: getRuleProviderCacheRuleCount(),
    providerCounts: getRuleProviderCacheProviderCounts(),
    providerUrls: {},
    providerOrder: [],
    providerName,
  }
}

const startBackgroundRuleRefresh = async (options = {}) => {
  const targetProviderName =
    typeof options.providerName === 'string' ? options.providerName.trim() : ''
  const referencedOnly = options.referencedOnly === true
  const requestedProviderNames = targetProviderName
    ? [targetProviderName]
    : Array.isArray(options.providerNames)
      ? [...new Set(options.providerNames.map((name) => String(name || '').trim()).filter(Boolean))]
      : []

  if (activeRuleRefreshPromise) {
    return {
      ok: true,
      started: false,
      ...getRuleRefreshResponsePayload({
        providerName: targetProviderName,
      }),
    }
  }

  const backend = readActiveBackendConfig()

  if (!backend) {
    throw new Error('No active backend configured')
  }

  const ruleSourceSnapshot = await assertRuleSourceReadyForSync()

  activeRuleRefreshController = new AbortController()
  ruleRefreshRunId += 1
  ruleRefreshState = {
    ...createDefaultRuleRefreshState(),
    runId: ruleRefreshRunId,
    isRefreshing: true,
    scope: requestedProviderNames.length === 1 ? 'provider' : 'all',
    providerName: targetProviderName,
    phase: 'provider',
    totalRules: getRuleProviderCacheRuleCount(),
  }

  activeRuleRefreshPromise = (async () => {
    let processedProviders = 0
    let providerErrors = 0

    try {
      const targetProviderNames = targetProviderName
        ? [targetProviderName]
        : referencedOnly
          ? getReferencedProviderNamesFromControllerRules(await fetchControllerRules(backend))
          : Array.isArray(options.providerNames)
            ? [
                ...new Set(
                  options.providerNames.map((name) => String(name || '').trim()).filter(Boolean),
                ),
              ]
            : []
      const providers = (await fetchControllerRuleProviders(backend))
        .filter(
          (provider) =>
            provider &&
            typeof provider === 'object' &&
            typeof provider.name === 'string' &&
            provider.name &&
            provider.vehicleType !== 'Inline',
        )
        .filter(
          (provider) =>
            targetProviderNames.length === 0 || targetProviderNames.includes(provider.name),
        )

      if (targetProviderNames.length > 0 && providers.length === 0) {
        throw new Error(
          targetProviderName
            ? `Rule provider not found: ${targetProviderName}`
            : 'Rule providers not found',
        )
      }

      setRuleRefreshState({
        totalProviders: providers.length,
      })

      for (const provider of providers) {
        if (activeRuleRefreshController.signal.aborted) {
          break
        }

        try {
          await controllerFetch(backend, `/providers/rules/${encodeURIComponent(provider.name)}`, {
            method: 'PUT',
          })
        } catch {
          if (activeRuleRefreshController.signal.aborted) {
            break
          }

          providerErrors += 1
        } finally {
          if (!activeRuleRefreshController.signal.aborted) {
            processedProviders += 1
            setRuleRefreshState({
              updatedProviders: processedProviders,
              errors: providerErrors,
            })
          }
        }
      }

      if (activeRuleRefreshController.signal.aborted) {
        setRuleRefreshState({
          isRefreshing: false,
          cancelled: true,
          completed: true,
          completedAt: Date.now(),
          phase: 'idle',
        })

        return
      }

      setRuleRefreshState({
        phase: 'cache',
        updatedProviders: providers.length,
      })

      const cacheResult = await updateRuleProviderCache({
        force: true,
        providerNames: targetProviderNames.length > 0 ? targetProviderNames : null,
        ruleSourceSnapshot,
      })
      const targetTotalRules =
        targetProviderNames.length > 0
          ? targetProviderNames.reduce((total, providerName) => {
              return total + (cacheResult.providerCounts?.[providerName] ?? 0)
            }, 0)
          : cacheResult.totalRules

      setRuleRefreshState({
        isRefreshing: false,
        phase: 'idle',
        totalRules: targetTotalRules,
        errors: providerErrors + cacheResult.errors.length,
        cancelled: cacheResult.cancelled,
        completed: true,
        completedAt: Date.now(),
        lastError:
          cacheResult.errors[0]?.message || (providerErrors > 0 ? 'provider refresh failed' : ''),
      })
    } catch (error) {
      const isCancelled = activeRuleRefreshController?.signal.aborted === true
      const message = error instanceof Error ? error.message : String(error)

      setRuleRefreshState({
        isRefreshing: false,
        phase: 'idle',
        cancelled: isCancelled,
        completed: true,
        completedAt: Date.now(),
        errors: providerErrors + (isCancelled ? 0 : 1),
        lastError: isCancelled ? '' : message,
      })
    } finally {
      activeRuleRefreshPromise = null
      activeRuleRefreshController = null
    }
  })()

  return {
    ok: true,
    started: true,
    ...getRuleRefreshResponsePayload({
      providerName: targetProviderName,
    }),
  }
}

const cancelBackgroundRuleRefresh = () => {
  let cancelled = false

  if (activeRuleRefreshController && !activeRuleRefreshController.signal.aborted) {
    activeRuleRefreshController.abort()
    cancelled = true
  }

  if (cancelRuleProviderUpdate()) {
    cancelled = true
  }

  if (cancelled) {
    setRuleRefreshState({
      isRefreshing: false,
      phase: 'idle',
      cancelled: true,
      completed: true,
      completedAt: Date.now(),
    })
  }

  return {
    ok: cancelled,
    ...getRuleRefreshResponsePayload({
      providerName: ruleRefreshState.providerName,
    }),
  }
}

const searchRuleProviderCache = async (query, options = {}) => {
  const lookup = normalizeLookupInput(query)

  if (!lookup) {
    throw new Error('query is invalid')
  }

  const lookups = [lookup]
  const rules = Array.isArray(options.rules) ? options.rules : []
  const providerNames = new Set(
    Array.isArray(options.providerNames) && options.providerNames.length > 0
      ? options.providerNames.map((name) => String(name || '').trim()).filter(Boolean)
      : getReferencedProviderNamesFromControllerRules(rules),
  )
  const hasProviderFilter = providerNames.size > 0

  const cachedProviders = getCachedRuleProviderStatement
    .all()
    .filter((provider) => !hasProviderFilter || providerNames.has(provider.name))
  const cachedSourceMetadata = getCachedRuleProviderSourceMetadata()
  const needsLiveSourceMetadata =
    cachedProviders.length > 0 &&
    cachedProviders.some(
      (provider) => !provider.source_url && !cachedSourceMetadata.providerUrls[provider.name],
    )
  const sourceMetadata = needsLiveSourceMetadata
    ? await getRuleProviderSourceMetadata()
    : cachedSourceMetadata
  const matches = []
  const unsupported = []
  const directRuleIndexes = []

  for (const provider of cachedProviders) {
    const providerMatches = await findMatchesInTextRulesByLookups(lookups, provider.body)

    if (providerMatches.length > 0) {
      matches.push({
        name: provider.name,
        behavior: provider.behavior,
        format: provider.format,
        url:
          sourceMetadata.providerUrls[provider.name] ||
          normalizeRuleProviderUrl(provider.source_url),
        totalRules: countRulesInBody(provider.body),
        status: 'cached',
        matches: sortRuleMatchesByLookup(lookup, providerMatches).slice(0, 20),
      })
    }
  }

  rules.forEach((rule) => {
    if (normalizeRuleTypeName(rule?.type) === 'RULE-SET') {
      return
    }

    const directRuleEntry = parseDirectControllerRuleEntry(rule)

    if (!directRuleEntry) {
      return
    }

    const directMatches = mergeLookupMatches(
      lookups.map((currentLookup) => findMatchesInTextRules(currentLookup, directRuleEntry.raw)),
    )

    if (directMatches.length > 0 && Number.isInteger(rule?.index)) {
      directRuleIndexes.push(rule.index)
      return
    }

    if (
      lookup.type === 'keyword' &&
      [rule.type, rule.payload, rule.proxy].some((value) =>
        String(value || '')
          .toLowerCase()
          .includes(lookup.value),
      ) &&
      Number.isInteger(rule?.index)
    ) {
      directRuleIndexes.push(rule.index)
    }
  })

  return {
    query: lookup.raw,
    queryType: lookup.type,
    mode: 'cached',
    matches,
    directRuleIndexes: [...new Set(directRuleIndexes)].sort((left, right) => left - right),
    unsupported,
    errors: [],
    totalProviders: sourceMetadata.providerOrder.length || cachedProviders.length,
    cachedProviders: cachedProviders.length,
  }
}

const app = express()
const server = http.createServer(app)
const websocketServer = new WebSocketServer({ noServer: true })

app.use('/api/auth', express.json({ limit: '2kb' }))
app.use('/api/rule-refresh', express.json({ limit: '2kb' }))
app.use('/api/rule-provider-penetration', express.json({ limit: '2kb' }))
app.use('/api/rule-provider-search', express.json({ limit: '128kb' }))
app.use('/api/storage', express.json({ limit: '25mb' }))
app.use('/api/openwrt-rule-source', express.json({ limit: '8kb' }))
app.use('/api/background-image', express.json({ limit: '25mb' }))
app.use('/api/custom-rules', express.json({ limit: '64kb' }))
app.use('/api/proxy-group-rule-penetration', express.json({ limit: '5mb' }))
app.use('/api/controller', express.raw({ type: '*/*', limit: '25mb' }))

app.get('/api/auth/status', (req, res) => {
  const authStatus = getRequestAccessAuthStatus(req)

  res.setHeader('Cache-Control', 'no-store')

  if (!authStatus.enabled) {
    clearAccessSessionCookie(res)
  }

  res.json(authStatus)
})

app.post('/api/auth/login', (req, res) => {
  const { enabled, password } = readAccessAuthConfig()

  res.setHeader('Cache-Control', 'no-store')

  if (!enabled) {
    clearAccessSessionCookie(res)
    res.json({
      enabled: false,
      authenticated: true,
    })
    return
  }

  const inputPassword = typeof req.body?.password === 'string' ? req.body.password : ''

  if (!safeTokenEquals(inputPassword, password)) {
    clearAccessSessionCookie(res)
    res.status(401).json({
      code: ACCESS_PASSWORD_INVALID_CODE,
      message: 'Invalid access password',
      enabled: true,
      authenticated: false,
    })
    return
  }

  setAccessSessionCookie(res, password)
  res.json({
    enabled: true,
    authenticated: true,
  })
})

app.post('/api/auth/logout', (_req, res) => {
  clearAccessSessionCookie(res)
  res.setHeader('Cache-Control', 'no-store')

  const { enabled } = readAccessAuthConfig()
  res.json({
    enabled,
    authenticated: !enabled,
  })
})

app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) {
    next()
    return
  }

  if (
    req.path === '/api/health' ||
    req.path === '/api/auth/status' ||
    req.path === '/api/auth/login' ||
    req.path === '/api/auth/logout'
  ) {
    next()
    return
  }

  const authStatus = getRequestAccessAuthStatus(req)

  if (!authStatus.enabled || authStatus.authenticated) {
    next()
    return
  }

  sendAccessPasswordRequired(res)
})

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    dbPath,
  })
})

app.get('/api/openwrt-rule-source/config', (_req, res) => {
  res.json({
    config: sanitizeOpenWrtRuleSourceSshConfig(readOpenWrtRuleSourceSshConfig()),
  })
})

app.put('/api/openwrt-rule-source/config', (req, res) => {
  const config = normalizeOpenWrtRuleSourceSshConfigInput(req.body?.config || req.body)

  try {
    saveOpenWrtRuleSourceSshConfig(config)

    res.json({
      ok: true,
      config: sanitizeOpenWrtRuleSourceSshConfig(readOpenWrtRuleSourceSshConfig()),
    })
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.post('/api/openwrt-rule-source/detect', async (req, res) => {
  const config = req.body?.config
    ? {
        ...normalizeOpenWrtRuleSourceSshConfigInput(req.body.config),
        configured: true,
      }
    : readOpenWrtRuleSourceSshConfig()

  try {
    const snapshot = await getOpenWrtRuleSourceSnapshot({
      config,
      required: true,
    })

    if (!snapshot) {
      throw new Error('OpenWrt SSH rule source is not configured.')
    }

    res.json({
      ok: true,
      plugin: snapshot.plugin,
      selectedPlugin: snapshot.selectedPlugin || snapshot.plugin,
      availablePlugins: snapshot.availablePlugins || [snapshot.plugin],
      pluginErrors: snapshot.pluginErrors || [],
      configPath: snapshot.configPath,
      providerCount: snapshot.providers.length,
      providers: snapshot.providers.slice(0, 20).map((provider) => ({
        name: provider.name,
        behavior: provider.behavior,
        format: provider.format,
        url: provider.url,
      })),
    })
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.post('/api/openwrt-rule-source/apply-custom', async (req, res) => {
  try {
    const settings = readCustomRulesSettings()
    const protocol = req.get('x-forwarded-proto') || req.protocol || 'http'
    const hostHeader = req.get('host') || `127.0.0.1:${port}`
    const ruleUrl = normalizeYamlInlineValue(
      req.body?.ruleUrl,
      `${protocol}://${hostHeader}/${settings.fileName}`,
    )
    const result = await applyCustomRuleProviderToOpenWrtYaml({ ruleUrl })

    res.json(result)
  } catch (error) {
    res.status(500).json({
      message: getErrorMessage(error),
      code: getErrorCode(error),
    })
  }
})

app.get('/api/openwrt-lan/discover', async (_req, res) => {
  try {
    res.json(await discoverOpenWrtLanHosts())
  } catch (error) {
    res.status(500).json({
      message: getErrorMessage(error),
    })
  }
})

app.all(/^\/api\/controller(?:\/.*)?$/, proxyControllerRequest)

app.get('/api/storage', (_req, res) => {
  res.json({
    entries: readSnapshot(),
  })
})

app.put('/api/storage', (req, res) => {
  const { entries } = req.body ?? {}

  if (!isValidEntries(entries)) {
    res.status(400).json({
      message: 'entries must be an object with string values',
    })
    return
  }

  replaceSnapshot(entries)

  res.json({
    ok: true,
    count: Object.keys(entries).length,
  })
})

app.get('/api/background-image', (_req, res) => {
  const row = getStorageValueStatement.get(backgroundImageStorageKey)

  res.json({
    image: row?.value || '',
  })
})

app.put('/api/background-image', (req, res) => {
  const { image } = req.body ?? {}

  if (typeof image !== 'string') {
    res.status(400).json({
      message: 'image must be a string',
    })
    return
  }

  upsertStorageValueStatement.run(backgroundImageStorageKey, image)

  res.json({
    ok: true,
    size: image.length,
  })
})

app.delete('/api/background-image', (_req, res) => {
  deleteStorageValueStatement.run(backgroundImageStorageKey)

  res.json({
    ok: true,
  })
})

app.post('/api/rule-provider-cache/update', async (_req, res) => {
  try {
    res.json(await updateRuleProviderCache())
  } catch (error) {
    res.status(500).json({
      code: getErrorCode(error),
      message: getLocalizedErrorMessage(error, _req),
    })
  }
})

app.post('/api/rule-provider-cache/cancel', (_req, res) => {
  res.json({
    ok: cancelRuleProviderUpdate(),
    progress: ruleProviderUpdateState,
  })
})

app.post('/api/rule-refresh/start', async (req, res) => {
  try {
    const providerName =
      typeof req.body?.providerName === 'string' ? req.body.providerName.trim() : ''
    const referencedOnly = req.body?.referencedOnly === true
    const providerNames = Array.isArray(req.body?.providerNames) ? req.body.providerNames : []

    res.json(
      await startBackgroundRuleRefresh({
        providerName,
        referencedOnly,
        providerNames,
      }),
    )
  } catch (error) {
    res.status(500).json({
      code: getErrorCode(error),
      message: getLocalizedErrorMessage(error, req),
    })
  }
})

app.post('/api/rule-refresh/cancel', (_req, res) => {
  res.json(cancelBackgroundRuleRefresh())
})

app.get('/api/rule-provider-cache/stats', async (_req, res) => {
  const sourceMetadata = await getRuleProviderSourceMetadata()

  res.json({
    totalRules: getRuleProviderCacheRuleCount(),
    providerCounts: getRuleProviderCacheProviderCounts(),
    providerUrls: sourceMetadata.providerUrls,
    providerOrder: sourceMetadata.providerOrder,
    progress: ruleProviderUpdateState,
    refresh: ruleRefreshState,
  })
})

app.get('/api/rule-provider-search', async (req, res) => {
  const query =
    typeof req.query.query === 'string'
      ? req.query.query
      : typeof req.query.domain === 'string'
        ? req.query.domain
        : ''

  if (!query.trim()) {
    res.status(400).json({
      message: 'query is required',
    })
    return
  }

  try {
    res.json(await searchRuleProviderCache(query))
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.post('/api/rule-provider-search', async (req, res) => {
  const query =
    typeof req.body?.query === 'string'
      ? req.body.query
      : typeof req.body?.domain === 'string'
        ? req.body.domain
        : ''
  const rules = Array.isArray(req.body?.rules) ? req.body.rules : []

  if (!query.trim()) {
    res.status(400).json({
      message: 'query is required',
    })
    return
  }

  try {
    res.json(
      await searchRuleProviderCache(query, {
        rules,
      }),
    )
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.post('/api/rule-provider-penetration', (req, res) => {
  const providerName =
    typeof req.body?.providerName === 'string' ? req.body.providerName.trim() : ''
  const page = normalizePositiveInteger(req.body?.page, 1, 10000)
  const pageSize = normalizePositiveInteger(req.body?.pageSize, 100, 500)
  const tab = normalizeProxyGroupRulePenetrationTab(req.body?.tab)
  const search = typeof req.body?.search === 'string' ? req.body.search.trim() : ''
  const sortKey = normalizeProxyGroupRulePenetrationSortKey(req.body?.sortKey)
  const sortDirection = normalizeProxyGroupRulePenetrationSortDirection(req.body?.sortDirection)

  if (!providerName) {
    res.status(400).json({
      message: 'providerName is required',
    })
    return
  }

  try {
    const cachedProvider = getCachedRuleProviderByNameStatement.get(providerName)

    if (!cachedProvider) {
      res.status(404).json({
        message: `Rule provider cache not found: ${providerName}`,
      })
      return
    }

    const allEntries = parseRuleEntriesFromBody(cachedProvider.body, providerName)
    const searchMatchedEntries = allEntries.filter((entry) =>
      matchesProxyGroupRulePenetrationSearch(entry, search),
    )
    const counts = buildRulePenetrationCounts(searchMatchedEntries)
    const tabMatchedEntries =
      tab === 'all'
        ? searchMatchedEntries
        : searchMatchedEntries.filter((entry) => entry.family === tab)
    const sortedEntries = sortProxyGroupRulePenetrationEntries(
      tabMatchedEntries,
      sortKey,
      sortDirection,
    )
    const start = (page - 1) * pageSize
    const end = start + pageSize

    res.json({
      cacheKey: '',
      providerName,
      totalRules: allEntries.length,
      totalMatched: tabMatchedEntries.length,
      counts,
      items: sortedEntries.slice(start, end),
      missingProviders: [],
      page,
      pageSize,
      hasMore: end < sortedEntries.length,
    })
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.post('/api/proxy-group-rule-penetration', (req, res) => {
  const groupName = typeof req.body?.groupName === 'string' ? req.body.groupName.trim() : ''
  const cacheKey = typeof req.body?.cacheKey === 'string' ? req.body.cacheKey.trim() : ''
  const rules = Array.isArray(req.body?.rules) ? req.body.rules : null
  const customGroupMode =
    normalizeProxyGroupCustomMode(req.body?.customGroupMode) ||
    getProxyGroupCustomModeFromGroupName(groupName)
  const customGroup = customGroupMode !== null || req.body?.customGroup === true
  const providerName =
    typeof req.body?.providerName === 'string' ? req.body.providerName.trim() : ''
  const page = normalizePositiveInteger(req.body?.page, 1, 10000)
  const pageSize = normalizePositiveInteger(req.body?.pageSize, 100, 500)
  const tab = normalizeProxyGroupRulePenetrationTab(req.body?.tab)
  const search = typeof req.body?.search === 'string' ? req.body.search.trim() : ''
  const sortKey = normalizeProxyGroupRulePenetrationSortKey(req.body?.sortKey)
  const sortDirection = normalizeProxyGroupRulePenetrationSortDirection(req.body?.sortDirection)

  if (!groupName) {
    res.status(400).json({
      message: 'groupName is required',
    })
    return
  }

  if (!cacheKey && !Array.isArray(rules)) {
    res.status(400).json({
      message: 'rules must be an array when cacheKey is missing',
    })
    return
  }

  try {
    const cacheEntry = getProxyGroupRulePenetrationCacheEntry({
      groupName,
      cacheKey,
      rules: rules || [],
      customGroup,
      customGroupMode,
    })
    const scopedEntries = providerName
      ? cacheEntry.items.filter((entry) => {
          return providerName === 'controller'
            ? entry.source === 'controller'
            : entry.source === providerName
        })
      : cacheEntry.items
    const searchMatchedEntries = scopedEntries.filter((entry) =>
      matchesProxyGroupRulePenetrationSearch(entry, search),
    )
    const counts = buildRulePenetrationCounts(searchMatchedEntries)

    const tabMatchedEntries =
      tab === 'all'
        ? searchMatchedEntries
        : searchMatchedEntries.filter((entry) => entry.family === tab)
    const sortedEntries = sortProxyGroupRulePenetrationEntries(
      tabMatchedEntries,
      sortKey,
      sortDirection,
    )
    const start = (page - 1) * pageSize
    const end = start + pageSize

    res.json({
      cacheKey: cacheEntry.cacheKey,
      groupName,
      customGroup,
      customGroupMode,
      providerName,
      totalRules: cacheEntry.totalRules,
      totalMatched: tabMatchedEntries.length,
      counts,
      items: sortedEntries.slice(start, end),
      missingProviders: cacheEntry.missingProviders,
      page,
      pageSize,
      hasMore: end < sortedEntries.length,
    })
  } catch (error) {
    if (error?.code === 'CACHE_EXPIRED') {
      res.status(410).json({
        message: 'cache expired',
      })
      return
    }

    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.get('/api/custom-rules', (req, res) => {
  const settings = readCustomRulesSettings()
  const protocol = req.get('x-forwarded-proto') || req.protocol || 'http'
  const hostHeader = req.get('host') || `127.0.0.1:${port}`
  const ruleUrl = `${protocol}://${hostHeader}/${settings.fileName}`

  res.setHeader('Cache-Control', 'no-store')
  res.json({
    rules: readCustomRules(),
    settings,
    ruleUrl,
    snippets: buildCustomRuleSnippets(ruleUrl),
  })
})

app.post('/api/custom-rules', (req, res) => {
  try {
    const result = addCustomRule({
      target: req.body?.target,
      kind: req.body?.kind || 'auto',
    })

    res.json(result)
  } catch (error) {
    res.status(400).json({
      message: getErrorMessage(error),
    })
  }
})

app.delete('/api/custom-rules', (req, res) => {
  const result = deleteCustomRule(req.body?.rule)

  res.json(result)
})

app.post('/api/custom-rules/settings', (req, res) => {
  try {
    const settings = updateCustomRulesSettings({
      policyGroup: req.body?.policyGroup,
      providerName: req.body?.providerName,
      fileName: req.body?.fileName,
    })

    res.json({ settings })
  } catch (error) {
    res.status(400).json({
      message: getErrorMessage(error),
    })
  }
})

app.get('/ziyong.list', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store')
  res.type('text/plain')
  res.send(readCustomRuleListText())
})

app.get('/sw.js', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
  res.type('application/javascript')
  res.send(serviceWorkerCleanupScript)
})

app.get('/registerSW.js', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
  res.type('application/javascript')
  res.send(registerSWCleanupScript)
})

if (fs.existsSync(distDir)) {
  app.use(
    express.static(distDir, {
      setHeaders: (res, filePath) => {
        const fileName = path.basename(filePath)

        if (
          fileName === 'index.html' ||
          fileName === 'sw.js' ||
          fileName === 'registerSW.js' ||
          fileName === 'manifest.webmanifest'
        ) {
          res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
          return
        }

        if (/^index-[A-Za-z0-9_-]+\.(js|css)$/.test(fileName)) {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable')
        }
      },
    }),
  )

  app.get(/^(?!\/api\/).*/, (_req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
    res.sendFile(path.join(distDir, 'index.html'))
  })
}

const writeUpgradeUnauthorized = (socket) => {
  socket.write(
    `HTTP/1.1 401 Unauthorized\r
Content-Type: application/json; charset=utf-8\r
Connection: close\r
\r
${JSON.stringify({
  code: ACCESS_PASSWORD_REQUIRED_CODE,
  message: 'Access password authentication required',
})}`,
  )
  socket.destroy()
}

server.on('upgrade', (request, socket, head) => {
  try {
    const requestUrl = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`)

    if (!requestUrl.pathname.startsWith('/api/controller-ws')) {
      socket.destroy()
      return
    }

    const authStatus = getUpgradeAccessAuthStatus(request)

    if (authStatus.enabled && !authStatus.authenticated) {
      writeUpgradeUnauthorized(socket)
      return
    }

    websocketServer.handleUpgrade(request, socket, head, (websocket) => {
      websocketServer.emit('connection', websocket, request)
    })
  } catch {
    socket.destroy()
  }
})

websocketServer.on('connection', relayControllerWebSocket)

const startServer = async () => {
  if (server.listening) {
    return server
  }

  await new Promise((resolve, reject) => {
    const handleError = (error) => {
      server.off('error', handleError)
      reject(error)
    }

    server.once('error', handleError)
    server.listen(port, host, () => {
      server.off('error', handleError)
      resolve()
    })
  })

  const address = server.address()
  const listenLabel =
    typeof address === 'object' && address
      ? `http://${address.address}:${address.port}`
      : `http://${host}:${port}`

  console.log(`zashboard server listening on ${listenLabel}`)
  console.log(`sqlite db: ${dbPath}`)
  startRuleProviderAutoRefresh()
  console.log(
    `rule-provider auto refresh check interval: ${Math.round(RULE_PROVIDER_AUTO_REFRESH_CHECK_MS / 1000)}s`,
  )

  return server
}

const shutdownServer = async () => {
  cancelRuleProviderUpdate()
  stopRuleProviderAutoRefresh()

  if (server.listening) {
    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error)
          return
        }

        resolve()
      })
    })
  }

  if (typeof db.close === 'function') {
    db.close()
  }
}

const isDirectExecution =
  Boolean(process.argv[1]) && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)

if (isDirectExecution) {
  startServer().catch((error) => {
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
  })
}

export {
  ACCESS_PASSWORD_INVALID_CODE,
  ACCESS_PASSWORD_REQUIRED_CODE,
  addCustomRule,
  app,
  applyCustomRuleProviderToYamlContent as applyCustomRuleProviderToYamlContentForTesting,
  buildCustomRuleSnippets,
  CLASH_CONTROLLER_DISCOVERY_PORTS as clashControllerDiscoveryPortsForTesting,
  createAccessSessionToken as createAccessSessionTokenForTesting,
  db,
  extractNikkiYamlConfigPathsFromProcessList as extractNikkiYamlConfigPathsFromProcessListForTesting,
  extractRemoteYamlConfigPathsFromText as extractRemoteYamlConfigPathsFromTextForTesting,
  extractRemoteYamlConfigPathsFromUci as extractRemoteYamlConfigPathsFromUciForTesting,
  getOpenWrtLanScanTargets as getOpenWrtLanScanTargetsForTesting,
  getRequestAccessAuthStatus as getRequestAccessAuthStatusForTesting,
  makeCustomRule,
  readCustomRuleListText,
  readCustomRules,
  readCustomRulesSettings,
  readSnapshot,
  replaceSnapshot,
  resolveOpenClashConfigPathFromUci as resolveOpenClashConfigPathFromUciForTesting,
  searchRuleProviderCache,
  seedRuleProviderCacheForTesting,
  server,
  shutdownServer,
  startServer,
  updateCustomRulesSettings,
}
