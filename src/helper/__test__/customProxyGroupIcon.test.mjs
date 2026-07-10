import assert from 'node:assert/strict'
import test from 'node:test'
import {
  CUSTOM_PROXY_GROUP_ICON,
  CUSTOM_PROXY_GROUP_ICON_UUID,
  ensureCustomProxyGroupIconInSettings,
} from '../customProxyGroupIcon.ts'

test('preserves renamed imported custom icon names and adds default aliases', () => {
  const settings = {
    'config/icon-reflect-list': JSON.stringify([
      { name: '我的分流', icon: CUSTOM_PROXY_GROUP_ICON, uuid: CUSTOM_PROXY_GROUP_ICON_UUID },
      { name: 'AI', icon: 'ai-icon', uuid: 'ai' },
    ]),
  }

  const result = ensureCustomProxyGroupIconInSettings(settings)
  const iconReflectList = JSON.parse(String(result['config/icon-reflect-list']))

  assert.equal(
    iconReflectList.find((item) => item.name === '我的分流')?.icon,
    CUSTOM_PROXY_GROUP_ICON,
  )
  assert.equal(
    iconReflectList.find((item) => item.name === '自定义')?.icon,
    CUSTOM_PROXY_GROUP_ICON,
  )
  assert.equal(iconReflectList.find((item) => item.name === '路飞')?.icon, CUSTOM_PROXY_GROUP_ICON)
  assert.equal(iconReflectList.find((item) => item.name === 'AI')?.icon, 'ai-icon')
})
