const serverUrlEl = document.querySelector('#server-url')
const defaultPolicyEl = document.querySelector('#default-policy')
const defaultKindEl = document.querySelector('#default-kind')
const preferRootDomainEl = document.querySelector('#prefer-root-domain')
const saveButton = document.querySelector('#save')
const testButton = document.querySelector('#test')
const statusEl = document.querySelector('#status')

const sendMessage = (message) => {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve))
}

const setStatus = (message, type = '') => {
  statusEl.textContent = message || ''
  statusEl.className = `status ${type}`.trim()
}

const getFormSettings = () => ({
  serverUrl: serverUrlEl.value.trim(),
  defaultPolicy: defaultPolicyEl.value,
  defaultKind: defaultKindEl.value,
  preferRootDomain: preferRootDomainEl.checked,
})

const loadSettings = async () => {
  const response = await sendMessage({ type: 'get-settings' })

  if (!response?.ok) {
    throw new Error(response?.message || '读取设置失败')
  }

  const settings = response.settings
  serverUrlEl.value = settings.serverUrl
  defaultPolicyEl.value = settings.defaultPolicy
  defaultKindEl.value = settings.defaultKind
  preferRootDomainEl.checked = settings.preferRootDomain !== false
}

saveButton.addEventListener('click', async () => {
  setStatus('正在保存...', '')
  const response = await sendMessage({ type: 'save-settings', settings: getFormSettings() })

  if (!response?.ok) {
    setStatus(response?.message || '保存失败', 'error')
    return
  }

  setStatus('设置已保存', 'ok')
})

testButton.addEventListener('click', async () => {
  testButton.disabled = true
  setStatus('正在测试连接...', '')

  try {
    const serverUrl = serverUrlEl.value.trim().replace(/\/+$/, '')
    const response = await fetch(`${serverUrl}/api/custom-rules`, {
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    })

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`)
    }

    const data = await response.json()
    setStatus(`连接成功，当前自定义规则 ${data.rules?.length || 0} 条`, 'ok')
  } catch (error) {
    setStatus(`连接失败：${error instanceof Error ? error.message : String(error)}`, 'error')
  } finally {
    testButton.disabled = false
  }
})

loadSettings().catch((error) =>
  setStatus(error instanceof Error ? error.message : String(error), 'error'),
)
