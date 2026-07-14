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
const refreshStatusButton = document.querySelector('#refresh-status')
const ruleStatusEl = document.querySelector('#rule-status')
const deleteRuleButton = document.querySelector('#delete-rule')
const switchPolicyButton = document.querySelector('#switch-policy')
const policyButtons = [...document.querySelectorAll('[data-policy]')]

let currentPolicy = 'proxy'
let currentDetected = { target: '', kind: 'domain_suffix', kindLabel: 'DOMAIN-SUFFIX' }
let currentSettings = null
let currentRuleStatus = null
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

const setRuleActionDisabled = (disabled) => {
  refreshStatusButton.disabled = disabled
  deleteRuleButton.disabled = disabled || !currentRuleStatus?.found
  switchPolicyButton.disabled = disabled || !currentDetected.target
}

const renderRuleStatus = (status) => {
  currentRuleStatus = status

  if (!status) {
    ruleStatusEl.textContent = '未读取'
    ruleStatusEl.className = 'rule-status'
    setRuleActionDisabled(false)
    return
  }

  if (status.found) {
    const policyText = status.policy === 'direct' ? '直连' : '代理'
    const conflictText = status.conflicts?.length ? `，另有 ${status.conflicts.length} 条重复` : ''

    ruleStatusEl.textContent = `已存在于${policyText}：${status.rule}${conflictText}`
    ruleStatusEl.className = `rule-status ${status.policy === 'direct' ? 'direct' : 'proxy'}`
  } else {
    ruleStatusEl.textContent = `未添加：${status.rule || currentDetected.target || '-'}`
    ruleStatusEl.className = 'rule-status empty'
  }

  setRuleActionDisabled(false)
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
  await refreshRuleStatus({ silent: true })
}

const refreshManualTarget = async () => {
  const target = manualTargetEl.value.trim()

  if (!target) {
    renderDetected({ target: '', kind: 'domain_suffix', kindLabel: 'DOMAIN-SUFFIX' })
    renderRuleStatus(null)
    return
  }

  if (isBatchTarget(target)) {
    kindEl.textContent = '规则类型：批量输入将逐行处理'
    ruleStatusEl.textContent = '批量输入请添加后到面板统一管理'
    ruleStatusEl.className = 'rule-status'
    currentRuleStatus = null
    setRuleActionDisabled(false)
    return
  }

  const response = await sendMessage({ type: 'detect-target', target })

  if (!response?.ok) {
    throw new Error(response?.message || '识别失败')
  }

  renderDetected(response.detected)
  await refreshRuleStatus({ silent: true })
}

const refreshRuleStatus = async ({ silent = false } = {}) => {
  const manualTarget = manualTargetEl.value.trim()

  if (!manualTarget && !currentDetected.target) {
    renderRuleStatus(null)
    return
  }

  if (manualTarget && isBatchTarget(manualTarget)) {
    ruleStatusEl.textContent = '批量输入请添加后到面板统一管理'
    ruleStatusEl.className = 'rule-status'
    currentRuleStatus = null
    setRuleActionDisabled(false)
    return
  }

  setRuleActionDisabled(true)
  if (!silent) {
    ruleStatusEl.textContent = '正在读取状态...'
    ruleStatusEl.className = 'rule-status'
  }

  try {
    await saveCurrentSettings()
    const response = await sendMessage({
      type: 'get-current-rule-status',
      kind: ruleKindEl.value,
      target: manualTarget || undefined,
    })

    if (!response?.ok) {
      throw new Error(response?.message || '读取状态失败')
    }

    renderRuleStatus(response.result)
  } catch (error) {
    currentRuleStatus = null
    ruleStatusEl.textContent = error instanceof Error ? error.message : String(error)
    ruleStatusEl.className = 'rule-status error'
    setRuleActionDisabled(false)
  }
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
    await refreshRuleStatus({ silent: true })
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
    await refreshRuleStatus({ silent: true })
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
  refreshRuleStatus({ silent: true }).catch((error) =>
    setStatus(error instanceof Error ? error.message : String(error), 'error'),
  )
})

refreshStatusButton.addEventListener('click', async () => {
  await refreshRuleStatus()
})

deleteRuleButton.addEventListener('click', async () => {
  deleteRuleButton.disabled = true
  setStatus('正在删除...', '')

  try {
    const response = await sendMessage({
      type: 'delete-current-rule',
      kind: ruleKindEl.value,
      target: manualTargetEl.value.trim() || undefined,
    })

    if (!response?.ok) {
      throw new Error(response?.message || '删除失败')
    }

    setStatus(response.result.removed ? '已删除并刷新规则源' : '当前规则不存在', 'ok')
    await refreshRuleStatus({ silent: true })
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), 'error')
  } finally {
    deleteRuleButton.disabled = false
    setRuleActionDisabled(false)
  }
})

switchPolicyButton.addEventListener('click', async () => {
  switchPolicyButton.disabled = true
  setStatus('正在切换策略...', '')

  try {
    const nextPolicy = currentRuleStatus?.policy === 'direct' ? 'proxy' : 'direct'
    const response = await sendMessage({
      type: 'switch-current-rule-policy',
      kind: ruleKindEl.value,
      target: manualTargetEl.value.trim() || undefined,
      policy: nextPolicy,
    })

    if (!response?.ok) {
      throw new Error(response?.message || '切换失败')
    }

    setPolicy(nextPolicy)
    setStatus(`已切换到${nextPolicy === 'direct' ? '直连' : '代理'}并刷新规则源`, 'ok')
    await refreshRuleStatus({ silent: true })
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), 'error')
  } finally {
    switchPolicyButton.disabled = false
    setRuleActionDisabled(false)
  }
})

refreshCurrentTab().catch((error) => {
  manualTargetEl.placeholder = '读取失败，可手动输入 example.com 或 1.1.1.1'
  setStatus(error instanceof Error ? error.message : String(error), 'error')
})
