const kindEl = document.querySelector('#kind')
const ruleKindEl = document.querySelector('#rule-kind')
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

const KIND_LABELS = {
  auto: '自动识别',
  domain_suffix: 'DOMAIN-SUFFIX',
  domain: 'DOMAIN',
  ip_cidr: 'IP-CIDR',
  raw: '原始规则',
}

const isBatchTarget = (value) => /[\r\n]/.test(value) || /^[A-Z][A-Z0-9-]*\s*,/.test(value.trim())

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

const renderDetected = (detected, options = {}) => {
  currentDetected = detected || { target: '', kind: 'domain_suffix', kindLabel: 'DOMAIN-SUFFIX' }
  const detectedKind = currentDetected.kind || 'domain_suffix'
  const autoOption = ruleKindEl.querySelector('option[value="auto"]')

  if (autoOption) {
    autoOption.textContent = currentDetected.target
      ? `自动识别（${currentDetected.kindLabel || KIND_LABELS[detectedKind] || detectedKind}）`
      : '自动识别'
  }

  if (detectedKind && ruleKindEl.value === 'auto') {
    ruleKindEl.value = detectedKind
  } else if (detectedKind && ruleKindEl.dataset.touched !== 'true') {
    ruleKindEl.value = detectedKind
  }

  if (options.syncInput) {
    manualTargetEl.value = currentDetected.target || ''
  }

  kindEl.textContent = currentDetected.target
    ? `已自动识别：${currentDetected.kindLabel}`
    : '规则类型：请输入目标或点击重新识别'
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
  renderDetected(response.detected, { syncInput: true })
}

const refreshManualTarget = async () => {
  const target = manualTargetEl.value.trim()

  if (!target) {
    renderDetected({ target: '', kind: 'domain_suffix', kindLabel: 'DOMAIN-SUFFIX' })
    return
  }

  if (isBatchTarget(target)) {
    kindEl.textContent = '规则类型：批量输入将逐行处理'
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
      kind: ruleKindEl.value,
      target: manualTarget || undefined,
    })

    if (!response?.ok) {
      throw new Error(response?.message || '添加失败')
    }

    const result = response.result
    const isBatchResult = Array.isArray(result.results)
    if (!isBatchResult) {
      renderDetected(
        { target: result.target, kind: result.kind, kindLabel: result.kindLabel },
        { syncInput: true },
      )
    }
    const refreshText = result.refresh?.started
      ? '，已自动刷新规则源'
      : result.refresh?.ok
        ? '，规则源正在刷新'
        : result.refresh?.message
          ? `，规则已保存但刷新失败：${result.refresh.message}`
          : ''
    const resultText = isBatchResult
      ? `批量完成：新增 ${result.addedCount || 0} 条，已存在 ${result.skippedCount || 0} 条${
          result.errorCount ? `，失败 ${result.errorCount} 条` : ''
        }`
      : `${result.added ? '已添加' : '已存在'}：${result.rule}`

    setStatus(`${resultText}${refreshText}`, 'ok')
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
    await refreshCurrentTab()
    setStatus('已重新识别当前网站', 'ok')
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), 'error')
  }
})

ruleKindEl.addEventListener('change', () => {
  ruleKindEl.dataset.touched = 'true'
})

refreshCurrentTab().catch((error) => {
  manualTargetEl.placeholder = '读取失败，可手动输入 example.com 或 1.1.1.1'
  setStatus(error instanceof Error ? error.message : String(error), 'error')
})
