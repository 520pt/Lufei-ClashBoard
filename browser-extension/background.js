const DEFAULT_SETTINGS = {
  serverUrl: 'http://127.0.0.1:2048',
  defaultPolicy: 'proxy',
  preferRootDomain: true,
}

const LUFEI_PANEL_PORT = 2048
const LUFEI_PANEL_PING_PATH = '/api/lufei-clashboard/ping'
const LAN_SCAN_TIMEOUT_MS = 650
const LAN_SCAN_CONCURRENCY = 32
const LAN_SCAN_SUBNETS = [
  '10.0.0',
  '10.0.1',
  '192.168.1',
  '192.168.0',
  '192.168.31',
  '192.168.2',
  '192.168.50',
  '172.16.0',
]
const LAN_SCAN_PRIORITY_HOSTS = [10, 11, 18, 20, 2, 3, 5, 100, 101, 200, 254, 1]

const POLICY_LABELS = {
  proxy: '代理',
  direct: '直连',
}

const RULE_KIND_LABELS = {
  auto: '自动识别',
  domain_suffix: 'DOMAIN-SUFFIX',
  domain: 'DOMAIN',
  ip_cidr: 'IP-CIDR',
  raw: '原始规则',
}

const KNOWN_TWO_PART_SUFFIXES = new Set([
  'com.cn',
  'net.cn',
  'org.cn',
  'gov.cn',
  'edu.cn',
  'co.uk',
  'org.uk',
  'ac.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.jp',
  'ne.jp',
  'or.jp',
  'com.hk',
  'net.hk',
  'org.hk',
  'com.tw',
  'net.tw',
  'org.tw',
])

const normalizeServerUrl = (value) => {
  const raw = String(value || '')
    .trim()
    .replace(/\/+$/, '')

  if (!raw) return DEFAULT_SETTINGS.serverUrl

  if (/^https?:\/\//i.test(raw)) return raw

  return `http://${raw}`
}

const getSettings = async () => {
  const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS)

  return {
    serverUrl: normalizeServerUrl(stored.serverUrl),
    defaultPolicy: stored.defaultPolicy === 'direct' ? 'direct' : 'proxy',
    preferRootDomain: stored.preferRootDomain !== false,
  }
}

const saveSettings = async (settings) => {
  await chrome.storage.sync.set({
    serverUrl: normalizeServerUrl(settings.serverUrl),
    defaultPolicy: settings.defaultPolicy === 'direct' ? 'direct' : 'proxy',
    preferRootDomain: settings.preferRootDomain !== false,
  })
}

const fetchJsonWithTimeout = async (url, timeoutMs = LAN_SCAN_TIMEOUT_MS) => {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const response = await fetch(url, {
      headers: { Accept: 'application/json' },
      cache: 'no-store',
      signal: controller.signal,
    })

    if (!response.ok) return null

    return await response.json().catch(() => null)
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

const isLufeiClashBoard = async (serverUrl) => {
  const baseUrl = normalizeServerUrl(serverUrl)
  const ping = await fetchJsonWithTimeout(`${baseUrl}${LUFEI_PANEL_PING_PATH}`)

  if (ping?.app === 'Lufei-ClashBoard') {
    return true
  }

  const customRules = await fetchJsonWithTimeout(`${baseUrl}/api/custom-rules`)

  return (
    Array.isArray(customRules?.rules) &&
    customRules?.settings?.fileName === 'ziyong.list' &&
    customRules?.settings?.directFileName === 'ziyong-direct.list'
  )
}

const buildLanScanCandidates = () => {
  const candidates = []
  const seen = new Set()
  const addCandidate = (host) => {
    const serverUrl = `http://${host}:${LUFEI_PANEL_PORT}`

    if (!seen.has(serverUrl)) {
      seen.add(serverUrl)
      candidates.push(serverUrl)
    }
  }

  LAN_SCAN_SUBNETS.forEach((subnet) => {
    LAN_SCAN_PRIORITY_HOSTS.forEach((host) => addCandidate(`${subnet}.${host}`))
  })

  LAN_SCAN_SUBNETS.forEach((subnet) => {
    for (let host = 1; host <= 254; host += 1) {
      addCandidate(`${subnet}.${host}`)
    }
  })

  return candidates
}

const findLufeiPanelOnLan = async () => {
  const candidates = buildLanScanCandidates()
  let index = 0
  let matchedUrl = ''

  const worker = async () => {
    while (!matchedUrl && index < candidates.length) {
      const serverUrl = candidates[index]
      index += 1

      if (await isLufeiClashBoard(serverUrl)) {
        matchedUrl = serverUrl
      }
    }
  }

  await Promise.all(Array.from({ length: LAN_SCAN_CONCURRENCY }, worker))

  return matchedUrl
}

const autoDetectServerUrlOnInstall = async () => {
  const stored = await chrome.storage.sync.get(['serverUrl'])
  const storedServerUrl = normalizeServerUrl(stored.serverUrl)

  if (stored.serverUrl && storedServerUrl !== DEFAULT_SETTINGS.serverUrl) {
    return
  }

  if (await isLufeiClashBoard(DEFAULT_SETTINGS.serverUrl)) {
    await chrome.storage.sync.set({ serverUrl: DEFAULT_SETTINGS.serverUrl })
    return
  }

  const detectedServerUrl = await findLufeiPanelOnLan()

  if (detectedServerUrl) {
    await chrome.storage.sync.set({ serverUrl: detectedServerUrl })
  }
}

const isIpv4Address = (host) => {
  const parts = String(host || '').split('.')

  return (
    parts.length === 4 &&
    parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)
  )
}

const isIpv6Address = (host) => {
  return String(host || '').includes(':') && /^[0-9a-f:]+$/i.test(host)
}

const isIpAddress = (host) => isIpv4Address(host) || isIpv6Address(host)

const getRegistrableDomain = (host) => {
  const parts = String(host || '')
    .toLowerCase()
    .replace(/^www\./, '')
    .split('.')
    .filter(Boolean)

  if (parts.length <= 2) return parts.join('.')

  const suffix2 = parts.slice(-2).join('.')
  const suffix3 = parts.slice(-3).join('.')

  if (KNOWN_TWO_PART_SUFFIXES.has(suffix2) && parts.length >= 3) {
    return suffix3
  }

  return suffix2
}

const extractHostFromUrl = (url) => {
  try {
    const parsed = new URL(url)

    if (!['http:', 'https:'].includes(parsed.protocol)) return ''

    return parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  } catch {
    return ''
  }
}

const normalizeManualTarget = (value) => {
  const raw = String(value || '').trim()

  if (!raw) return ''

  if (/^https?:\/\//i.test(raw)) {
    return extractHostFromUrl(raw)
  }

  return raw
    .replace(/^\[|\]$/g, '')
    .replace(/^www\./, '')
    .toLowerCase()
}

const detectRuleFromHost = ({ host, preferRootDomain = true } = {}) => {
  const normalizedHost = normalizeManualTarget(host)

  if (!normalizedHost) {
    return { target: '', kind: 'domain_suffix', kindLabel: RULE_KIND_LABELS.domain_suffix }
  }

  if (isIpAddress(normalizedHost)) {
    return { target: normalizedHost, kind: 'ip_cidr', kindLabel: RULE_KIND_LABELS.ip_cidr }
  }

  const target = preferRootDomain ? getRegistrableDomain(normalizedHost) : normalizedHost

  return { target, kind: 'domain_suffix', kindLabel: RULE_KIND_LABELS.domain_suffix }
}

const detectRuleFromUrl = ({ url, preferRootDomain = true } = {}) => {
  return detectRuleFromHost({ host: extractHostFromUrl(url), preferRootDomain })
}

const getActiveTab = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })

  return tab || null
}

const addCustomRule = async ({ target, kind, policy, serverUrl }) => {
  const response = await fetch(`${normalizeServerUrl(serverUrl)}/api/custom-rules`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ target, kind, policy }),
  })
  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new Error(data.message || `请求失败：HTTP ${response.status}`)
  }

  return data
}

const notify = async (title, message) => {
  await chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon-192.png',
    title,
    message,
  })
}

const normalizeRuleKind = (kind, fallback = 'domain_suffix') => {
  const normalized = String(kind || '')
    .trim()
    .toLowerCase()
    .replace(/-/g, '_')

  return Object.prototype.hasOwnProperty.call(RULE_KIND_LABELS, normalized) ? normalized : fallback
}

const isCompleteRuleLine = (value) => /^[A-Z][A-Z0-9-]*\s*,/.test(String(value || '').trim())

const isBatchRuleTarget = (value) => {
  const raw = String(value || '').trim()

  return /[\r\n]/.test(raw) || isCompleteRuleLine(raw) || /[\s,;，；]/.test(raw)
}

const addCurrentTabRule = async ({ policy, kind, target: targetOverride, url } = {}) => {
  const settings = await getSettings()
  const tab = await getActiveTab()
  const rawTargetOverride = String(targetOverride || '').trim()
  const batchTarget = rawTargetOverride && isBatchRuleTarget(rawTargetOverride)
  const detected =
    rawTargetOverride && !batchTarget
      ? detectRuleFromHost({ host: targetOverride, preferRootDomain: settings.preferRootDomain })
      : detectRuleFromUrl({
          url: url || tab?.url || '',
          preferRootDomain: settings.preferRootDomain,
        })
  const finalPolicy = policy || settings.defaultPolicy
  const finalKind = normalizeRuleKind(kind, detected.kind)

  if (!batchTarget && !detected.target) {
    throw new Error('当前页面不是可添加的 http/https 网站')
  }

  const result = await addCustomRule({
    target: batchTarget ? rawTargetOverride : detected.target,
    kind: finalKind,
    policy: finalPolicy,
    serverUrl: settings.serverUrl,
  })
  const summary = Array.isArray(result.results)
    ? `新增 ${result.addedCount || 0} 条，已存在 ${result.skippedCount || 0} 条${
        result.errorCount ? `，失败 ${result.errorCount} 条` : ''
      }`
    : `${result.added ? '已添加' : '已存在'}到${POLICY_LABELS[finalPolicy]}：${result.rule}`

  await notify('LuFei 自定义规则', summary)

  return {
    ...result,
    target: batchTarget ? rawTargetOverride : detected.target,
    policy: finalPolicy,
    kind: finalKind,
    kindLabel: finalKind === 'auto' ? detected.kindLabel : RULE_KIND_LABELS[finalKind],
    serverUrl: settings.serverUrl,
  }
}

const testConnection = async (serverUrl) => {
  const response = await fetch(`${normalizeServerUrl(serverUrl)}/api/custom-rules`, {
    headers: { Accept: 'application/json' },
    cache: 'no-store',
  })
  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new Error(data.message || `HTTP ${response.status}`)
  }

  return {
    rules: Array.isArray(data.rules) ? data.rules.length : 0,
    ruleUrl: data.ruleUrl || '',
  }
}

const createContextMenus = () => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: 'lufei-add-proxy',
      title: '添加当前网站到自定义代理',
      contexts: ['page', 'link'],
    })
    chrome.contextMenus.create({
      id: 'lufei-add-direct',
      title: '添加当前网站到自定义直连',
      contexts: ['page', 'link'],
    })
  })
}

chrome.runtime.onInstalled.addListener((details) => {
  createContextMenus()

  if (details.reason === 'install' || details.reason === 'update') {
    autoDetectServerUrlOnInstall().catch((error) => {
      console.warn('[LuFei] 自动检测面板地址失败', error)
    })
  }
})
chrome.runtime.onStartup.addListener(createContextMenus)

chrome.contextMenus.onClicked.addListener(async (info) => {
  try {
    const policy = info.menuItemId === 'lufei-add-direct' ? 'direct' : 'proxy'
    await addCurrentTabRule({ policy, url: info.linkUrl || info.pageUrl })
  } catch (error) {
    await notify('添加失败', error instanceof Error ? error.message : String(error))
  }
})

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  ;(async () => {
    if (message?.type === 'get-settings') {
      sendResponse({ ok: true, settings: await getSettings() })
      return
    }

    if (message?.type === 'save-settings') {
      await saveSettings(message.settings || {})
      sendResponse({ ok: true, settings: await getSettings() })
      return
    }

    if (message?.type === 'get-current-tab') {
      const settings = await getSettings()
      const tab = await getActiveTab()
      const detected = detectRuleFromUrl({
        url: tab?.url || '',
        preferRootDomain: settings.preferRootDomain,
      })

      sendResponse({ ok: true, tab, detected, settings })
      return
    }

    if (message?.type === 'detect-target') {
      const settings = await getSettings()
      sendResponse({
        ok: true,
        detected: detectRuleFromHost({
          host: message.target || '',
          preferRootDomain: settings.preferRootDomain,
        }),
      })
      return
    }

    if (message?.type === 'add-current-tab-rule') {
      sendResponse({ ok: true, result: await addCurrentTabRule(message) })
      return
    }

    if (message?.type === 'test-connection') {
      sendResponse({ ok: true, result: await testConnection(message.serverUrl) })
      return
    }

    sendResponse({ ok: false, message: '未知操作' })
  })().catch((error) => {
    sendResponse({ ok: false, message: error instanceof Error ? error.message : String(error) })
  })

  return true
})
