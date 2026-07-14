import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DOMAIN_GROUP_POST_CUSTOM_KEY,
  DOMAIN_GROUP_PRE_CUSTOM_KEY,
  getDomainGroupNames,
} from '../proxyDomainGroups.ts'

test('domain groups always include pre and post custom groups for first rule creation', () => {
  assert.deepEqual(getDomainGroupNames([], ['香港', '其他']), [
    DOMAIN_GROUP_PRE_CUSTOM_KEY,
    '香港',
    DOMAIN_GROUP_POST_CUSTOM_KEY,
    '其他',
  ])
})
