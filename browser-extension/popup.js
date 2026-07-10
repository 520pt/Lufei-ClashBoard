const targetEl = document.querySelector('#target')
const kindEl = document.querySelector('#kind')
const statusEl = document.querySelector('#status')
const serverUrlEl = document.querySelector('#server-url')
const manualTargetEl = document.querySelector('#manual-target')
const preferRootDomainEl = document.querySelector('#prefer-root-domain')
const addButton = document.querySelector('#add')
const saveSettingsButton = document.querySelector('#save-settings')
const testConnectionButton = document.querySelector('#test-connection')
const openPanelButton = document.querySelector('#open-panel')
const refreshButton = document.querySelector('#refresh')
const policyButtons = [...document.querySelectorAll('[data-policy]')]

let currentPolicy = 'proxy'
let currentDetected = { target: '', kind: 'domain_suffix', kindLabel: 'DOMAIN-SUFFIX' }
let currentSettings = null
let manualDetectTimer = 0

const sendMessage = (message) => {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, resolve)
  })
}

const setStatus = (message, type = '') => {
  statusEl.textContent = message || ''
  statusEl.className = `status ${type}`.trim()
}

const setPolicy = (policy) => {
  currentPolicy = policy === 'direct' ? 'direct' : 'proxy'
  policyButtons.forEach((button) => {
    button.classList.toggle('active', button.dataset.policy === currentPolicy)
  })
}

const renderDetected = (detected) => {
  currentDetected = detected || { target: '', kind: 'domain_suffix', kindLabel: 'DOMAIN-SUFFIX' }
  targetEl.textContent = currentDetected.target || '当前页面不可添加'
  kindEl.textContent = currentDetected.target
    ? `规则类型：${currentDetected.kindLabel}`
    : '规则类型：无法识别'
}

const getFormSettings = () => ({
  serverUrl: serverUrlEl.value.trim(),
  defaultPolicy: currentPolicy,
  preferRootDomain: preferRootDomainEl.checked,
})

const saveCurrentSettings = async () => {
  const response = await sendMessage({ type: 'save-settings', settings: getFormSettings() })

  if (!response?.ok) {
    throw new Error(response?.message || '保存失败')
  }

  currentSettings = response.settings
  return currentSettings
}

const refreshCurrentTab = async () => {
  const response = await sendMessage({ type: 'get-current-tab' })

  if (!response?.ok) {
    throw new Error(response?.message || '读取当前标签页失败')
  }

  currentSettings = response.settings
  serverUrlEl.value = currentSettings.serverUrl
  preferRootDomainEl.checked = currentSettings.preferRootDomain !== false
  setPolicy(currentSettings.defaultPolicy || 'proxy')
  renderDetected(response.detected)
}

const refreshManualTarget = async () => {
  const target = manualTargetEl.value.trim()

  if (!target) {
    await refreshCurrentTab()
    return
  }

  const response = await sendMessage({ type: 'detect-target', target })

  if (!response?.ok) {
    throw new Error(response?.message || '识别失败')
  }

  renderDetected(response.detected)
}

policyButtons.forEach((button) => {
  button.addEventListener('click', () => setPolicy(button.dataset.policy))
})

manualTargetEl.addEventListener('input', () => {
  window.clearTimeout(manualDetectTimer)
  manualDetectTimer = window.setTimeout(() => {
    refreshManualTarget().catch((error) => setStatus(error.message || String(error), 'error'))
  }, 160)
})

preferRootDomainEl.addEventListener('change', async () => {
  try {
    await saveCurrentSettings()
    await refreshManualTarget()
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), 'error')
  }
})

saveSettingsButton.addEventListener('click', async () => {
  try {
    await saveCurrentSettings()
    setStatus('面板地址已保存', 'ok')
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), 'error')
  }
})

testConnectionButton.addEventListener('click', async () => {
  testConnectionButton.disabled = true
  setStatus('正在测试连接...', '')

  try {
    const response = await sendMessage({ type: 'test-connection', serverUrl: serverUrlEl.value })

    if (!response?.ok) {
      throw new Error(response?.message || '连接失败')
    }

    setStatus(`连接成功，当前自定义规则 ${response.result.rules} 条`, 'ok')
  } catch (error) {
    setStatus(`连接失败：${error instanceof Error ? error.message : String(error)}`, 'error')
  } finally {
    testConnectionButton.disabled = false
  }
})

addButton.addEventListener('click', async () => {
  addButton.disabled = true
  setStatus('正在添加...', '')

  try {
    await saveCurrentSettings()
    const manualTarget = manualTargetEl.value.trim()
    const response = await sendMessage({
      type: 'add-current-tab-rule',
      policy: currentPolicy,
      target: manualTarget || undefined,
    })

    if (!response?.ok) {
      throw new Error(response?.message || '添加失败')
    }

    const result = response.result
    renderDetected({ target: result.target, kind: result.kind, kindLabel: result.kindLabel })
    setStatus(`${result.added ? '已添加' : '已存在'}：${result.rule}`, 'ok')
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), 'error')
  } finally {
    addButton.disabled = false
  }
})

openPanelButton.addEventListener('click', async () => {
  const settings = currentSettings || (await sendMessage({ type: 'get-settings' })).settings
  chrome.tabs.create({ url: settings.serverUrl })
})

refreshButton.addEventListener('click', async () => {
  try {
    manualTargetEl.value = ''
    await refreshCurrentTab()
    setStatus('已重新识别当前网站', 'ok')
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), 'error')
  }
})

refreshCurrentTab().catch((error) => {
  targetEl.textContent = '读取失败'
  setStatus(error instanceof Error ? error.message : String(error), 'error')
})
