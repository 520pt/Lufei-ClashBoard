const DEFAULT_SETTINGS = {
  serverUrl: 'http://10.0.0.11:2048',
  defaultPolicy: 'proxy',
  defaultKind: 'domain_suffix',
  preferRootDomain: true,
}

const POLICY_LABELS = {
  proxy: '代理',
  direct: '直连',
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
    defaultKind: ['auto', 'domain', 'domain_suffix', 'ip_cidr'].includes(stored.defaultKind)
      ? stored.defaultKind
      : 'domain_suffix',
    preferRootDomain: stored.preferRootDomain !== false,
  }
}

const saveSettings = async (settings) => {
  await chrome.storage.sync.set({
    serverUrl: normalizeServerUrl(settings.serverUrl),
    defaultPolicy: settings.defaultPolicy === 'direct' ? 'direct' : 'proxy',
    defaultKind: ['auto', 'domain', 'domain_suffix', 'ip_cidr'].includes(settings.defaultKind)
      ? settings.defaultKind
      : 'domain_suffix',
    preferRootDomain: settings.preferRootDomain !== false,
  })
}

const isIpAddress = (host) => {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || /^[0-9a-f:]+$/i.test(host)
}

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

const buildRuleTarget = ({ url, preferRootDomain = true, kind = 'domain_suffix' }) => {
  const host = extractHostFromUrl(url)

  if (!host) return ''

  if (isIpAddress(host)) return host

  if (kind === 'domain' || preferRootDomain === false) return host

  return getRegistrableDomain(host)
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

const addCurrentTabRule = async ({ policy, kind, target: targetOverride, url } = {}) => {
  const settings = await getSettings()
  const tab = await getActiveTab()
  const finalKind = kind || settings.defaultKind
  const finalPolicy = policy || settings.defaultPolicy
  const target =
    String(targetOverride || '').trim() ||
    buildRuleTarget({
      url: url || tab?.url || '',
      preferRootDomain: settings.preferRootDomain,
      kind: finalKind,
    })

  if (!target) {
    throw new Error('当前页面不是可添加的 http/https 网站')
  }

  const result = await addCustomRule({
    target,
    kind: finalKind,
    policy: finalPolicy,
    serverUrl: settings.serverUrl,
  })

  await notify(
    'LuFei 自定义规则',
    `${result.added ? '已添加' : '已存在'}到${POLICY_LABELS[finalPolicy]}：${result.rule}`,
  )

  return {
    ...result,
    target,
    policy: finalPolicy,
    kind: finalKind,
    serverUrl: settings.serverUrl,
  }
}

const openOptionsPage = () => {
  chrome.runtime.openOptionsPage()
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
    chrome.contextMenus.create({
      id: 'lufei-options',
      title: '打开 LuFei 插件设置',
      contexts: ['action'],
    })
  })
}

chrome.runtime.onInstalled.addListener(createContextMenus)
chrome.runtime.onStartup.addListener(createContextMenus)

chrome.contextMenus.onClicked.addListener(async (info) => {
  try {
    if (info.menuItemId === 'lufei-options') {
      openOptionsPage()
      return
    }

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
      const target = buildRuleTarget({
        url: tab?.url || '',
        preferRootDomain: settings.preferRootDomain,
        kind: settings.defaultKind,
      })

      sendResponse({ ok: true, tab, target, settings })
      return
    }

    if (message?.type === 'add-current-tab-rule') {
      sendResponse({ ok: true, result: await addCurrentTabRule(message) })
      return
    }

    sendResponse({ ok: false, message: '未知操作' })
  })().catch((error) => {
    sendResponse({ ok: false, message: error instanceof Error ? error.message : String(error) })
  })

  return true
})
