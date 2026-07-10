const targetEl = document.querySelector('#target')
const serverEl = document.querySelector('#server')
const statusEl = document.querySelector('#status')
const kindEl = document.querySelector('#kind')
const manualTargetEl = document.querySelector('#manual-target')
const addButton = document.querySelector('#add')
const optionButton = document.querySelector('#options')
const openPanelButton = document.querySelector('#open-panel')
const policyButtons = [...document.querySelectorAll('[data-policy]')]

let currentPolicy = 'proxy'
let currentTarget = ''
let currentSettings = null

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

const refreshCurrentTab = async () => {
  const response = await sendMessage({ type: 'get-current-tab' })

  if (!response?.ok) {
    throw new Error(response?.message || '读取当前标签页失败')
  }

  currentSettings = response.settings
  currentTarget = response.target || ''
  targetEl.textContent = currentTarget || '当前页面不可添加'
  serverEl.textContent = `面板地址：${currentSettings.serverUrl}`
  kindEl.value = currentSettings.defaultKind || 'domain_suffix'
  setPolicy(currentSettings.defaultPolicy || 'proxy')
}

policyButtons.forEach((button) => {
  button.addEventListener('click', () => setPolicy(button.dataset.policy))
})

kindEl.addEventListener('change', async () => {
  currentSettings = currentSettings || {}
  currentSettings.defaultKind = kindEl.value
})

addButton.addEventListener('click', async () => {
  addButton.disabled = true
  setStatus('正在添加...', '')

  try {
    const manualTarget = manualTargetEl.value.trim()
    const response = manualTarget
      ? await sendMessage({
          type: 'add-current-tab-rule',
          policy: currentPolicy,
          kind: kindEl.value,
          target: manualTarget,
        })
      : await sendMessage({
          type: 'add-current-tab-rule',
          policy: currentPolicy,
          kind: kindEl.value,
        })

    if (!response?.ok) {
      throw new Error(response?.message || '添加失败')
    }

    const result = response.result
    setStatus(`${result.added ? '已添加' : '已存在'}：${result.rule}`, 'ok')
  } catch (error) {
    setStatus(error instanceof Error ? error.message : String(error), 'error')
  } finally {
    addButton.disabled = false
  }
})

optionButton.addEventListener('click', () => chrome.runtime.openOptionsPage())
openPanelButton.addEventListener('click', async () => {
  const settings = currentSettings || (await sendMessage({ type: 'get-settings' })).settings
  chrome.tabs.create({ url: settings.serverUrl })
})

refreshCurrentTab().catch((error) => {
  targetEl.textContent = '读取失败'
  setStatus(error instanceof Error ? error.message : String(error), 'error')
})
