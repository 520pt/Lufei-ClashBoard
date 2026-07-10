import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test, { after } from 'node:test'

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ange-clashboard-test-'))
const dbPath = path.join(tempDir, 'zashboard.sqlite')

process.env.ZASHBOARD_DB_PATH = dbPath
delete process.env.ZASHBOARD_OPENWRT_SSH_HOST
delete process.env.ZASHBOARD_OPENWRT_SSH_PORT
delete process.env.ZASHBOARD_OPENWRT_SSH_USER
delete process.env.ZASHBOARD_OPENWRT_SSH_USERNAME
delete process.env.ZASHBOARD_OPENWRT_SSH_PASSWORD
delete process.env.ZASHBOARD_RULE_SOURCE_PLUGIN

const serverModuleUrl = new URL(`./../index.mjs?test=${Date.now()}`, import.meta.url)
const {
  addCustomRule,
  addCustomRules,
  applyCustomRuleProviderToYamlContentForTesting,
  buildPublicCustomRuleUrlForTesting,
  buildCustomRuleSnippets,
  clashControllerDiscoveryPortsForTesting,
  createAccessSessionTokenForTesting,
  deleteCustomRuleForTesting,
  extractOpenWrtVisibleClientIpv4ForTesting,
  extractNikkiYamlConfigPathsFromProcessListForTesting,
  extractRemoteYamlConfigPathsFromTextForTesting,
  extractRemoteYamlConfigPathsFromUciForTesting,
  getOpenWrtDiscoveryConcurrencyForTesting,
  getOpenWrtHttpSignalsForTesting,
  getOpenWrtLanScanTargetsForTesting,
  getOpenWrtLanScanTargetsFromSubnetForTesting,
  getProxyGroupRulePenetrationCacheEntryForTesting,
  getRemoteYamlBackupCleanupCommandForTesting,
  getRemoteYamlBackupPathForTesting,
  getRequestAccessAuthStatusForTesting,
  isLikelyClashControllerResultForTesting,
  makeCustomRule,
  readCustomRuleListText,
  readCustomRules,
  readCustomRulesSettings,
  readSnapshot,
  replaceManagedSnapshotForTesting,
  replaceSnapshot,
  replaceCustomRulesTextForTesting,
  restoreCustomRulesFromBackupForTesting,
  resolveOpenClashConfigPathFromUciForTesting,
  searchRuleProviderCache,
  seedRuleProviderCacheForTesting,
  shouldIncludeOpenWrtCandidateForTesting,
  shutdownServer,
  syncCustomRuleProvidersToCacheForTesting,
  updateCustomRulesSettings,
} = await import(serverModuleUrl.href)

after(async () => {
  await shutdownServer().catch(() => {})
  await fs.rm(tempDir, { recursive: true, force: true })
})

test('service auth state is enforced from persisted settings', () => {
  replaceSnapshot({
    'config/access-password-enabled': 'true',
    'config/access-password': 'test-secret',
  })

  assert.deepEqual(
    getRequestAccessAuthStatusForTesting({
      headers: {},
    }),
    {
      enabled: true,
      authenticated: false,
    },
  )

  assert.deepEqual(
    getRequestAccessAuthStatusForTesting({
      headers: {
        cookie: `ange_clashboard_access_session=${createAccessSessionTokenForTesting('test-secret')}`,
      },
    }),
    {
      enabled: true,
      authenticated: true,
    },
  )
})

test('rule provider search returns cached matches', async () => {
  seedRuleProviderCacheForTesting([
    {
      name: 'streaming',
      behavior: 'domain',
      format: 'text',
      url: 'https://example.test/streaming.txt',
      body: `DOMAIN-SUFFIX,netflix.com
DOMAIN,api.openai.com
`,
    },
  ])

  const payload = await searchRuleProviderCache('www.netflix.com')

  assert.equal(payload.totalProviders, 1)
  assert.equal(payload.cachedProviders, 1)
  assert.equal(payload.matches.length, 1)
  assert.equal(payload.matches[0].name, 'streaming')
  assert.equal(payload.matches[0].totalRules, 2)
  assert.deepEqual(payload.matches[0].matches[0], {
    line: 1,
    value: 'netflix.com',
    mode: 'suffix',
    raw: 'DOMAIN-SUFFIX,netflix.com',
  })
})

test('rule provider search does not require live OpenWrt SSH config', async () => {
  seedRuleProviderCacheForTesting([
    {
      name: 'streaming',
      behavior: 'domain',
      format: 'text',
      url: 'https://example.test/streaming.txt',
      body: `DOMAIN-SUFFIX,netflix.com
DOMAIN,api.openai.com
`,
    },
  ])

  const payload = await searchRuleProviderCache('www.netflix.com')

  assert.equal(payload.cachedProviders, 1)
  assert.equal(payload.matches.length, 1)
  assert.equal(payload.matches[0].name, 'streaming')
  assert.equal(payload.matches[0].url, 'https://example.test/streaming.txt')
})

test('OpenClash config_path is resolved from UCI config without guessing provider URLs', () => {
  assert.equal(
    resolveOpenClashConfigPathFromUciForTesting(
      `
config openclash 'config'
  option config_path '/etc/openclash/config/live.yaml'
`,
    ),
    '/etc/openclash/config/live.yaml',
  )

  assert.equal(
    resolveOpenClashConfigPathFromUciForTesting(
      `
config openclash 'config'
  option config_path 'active.yaml'
`,
      {
        configDir: '/tmp/openclash/config',
        uciConfigPath: '/tmp/openclash/uci',
      },
    ),
    '/tmp/openclash/config/active.yaml',
  )
})

test('Nikki YAML paths are extracted from remote process and UCI content', () => {
  assert.deepEqual(
    extractRemoteYamlConfigPathsFromTextForTesting(
      `1234 root /usr/bin/mihomo -d /etc/nikki/run -f /tmp/nikki/live/config.yaml
5678 root /usr/bin/other --config=/etc/example/ignored.json
`,
    ),
    ['/tmp/nikki/live/config.yaml'],
  )

  assert.deepEqual(
    extractRemoteYamlConfigPathsFromUciForTesting(
      `
config nikki 'config'
  option profile '/etc/nikki/profiles/home.yaml'
  list include "/tmp/nikki/rules/current.yml"
`,
    ),
    ['/etc/nikki/profiles/home.yaml', '/tmp/nikki/rules/current.yml'],
  )
})

test('Nikki process detection ignores OpenClash-owned YAML paths', () => {
  assert.deepEqual(
    extractNikkiYamlConfigPathsFromProcessListForTesting(
      `1234 root /usr/bin/mihomo -d /etc/openclash/core -f /etc/openclash/clash-fallback-std-cn-one.yaml
5678 root /usr/bin/mihomo -d /etc/nikki/run -f /tmp/nikki/live/config.yaml
9012 root /usr/bin/nikki --config=/tmp/custom-nikki.yaml
`,
    ),
    ['/tmp/nikki/live/config.yaml', '/tmp/custom-nikki.yaml'],
  )
})

test('OpenWrt LAN discovery builds private /24 scan targets', () => {
  const targets = getOpenWrtLanScanTargetsForTesting(['192.168.3.88'])

  assert.equal(targets.includes('192.168.3.1'), true)
  assert.equal(targets.includes('192.168.3.254'), true)
  assert.equal(targets.includes('192.168.3.88'), false)
  assert.equal(targets.length, 253)
})

test('OpenWrt LAN discovery scans common Clash controller ports', () => {
  assert.deepEqual(
    clashControllerDiscoveryPortsForTesting,
    [9090, 9091, 9092, 9093, 9097, 19090, 19091],
  )
})

test('OpenWrt LAN discovery builds targets from custom private subnet', () => {
  assert.deepEqual(getOpenWrtLanScanTargetsFromSubnetForTesting('10.0.0.0/30'), [
    '10.0.0.1',
    '10.0.0.2',
  ])

  assert.deepEqual(getOpenWrtLanScanTargetsFromSubnetForTesting('192.168.3.88'), ['192.168.3.88'])
})

test('OpenWrt LAN discovery rejects public or too large custom subnet', () => {
  assert.throws(
    () => getOpenWrtLanScanTargetsFromSubnetForTesting('8.8.8.0/24'),
    /只能扫描私有 IPv4 网段/,
  )

  assert.throws(
    () => getOpenWrtLanScanTargetsFromSubnetForTesting('10.0.0.0/22'),
    /最多扫描 512 个地址/,
  )
})

test('OpenWrt LAN discovery lowers concurrency for large subnets', () => {
  assert.equal(getOpenWrtDiscoveryConcurrencyForTesting(1), 32)
  assert.equal(getOpenWrtDiscoveryConcurrencyForTesting(32), 32)
  assert.equal(getOpenWrtDiscoveryConcurrencyForTesting(254), 16)
  assert.equal(getOpenWrtDiscoveryConcurrencyForTesting(510), 16)
})

test('OpenWrt LAN discovery excludes Xiaomi router LuCI-like pages', () => {
  const signals = getOpenWrtHttpSignalsForTesting({
    text: '<title>小米路由器</title><meta http-equiv="refresh" content="0; url=/cgi-bin/luci/web" />',
    headers: {
      server: 'nginx/1.12.2',
    },
  })

  assert.equal(signals.hasOpenWrtHint, false)
  assert.equal(signals.hasExcludedRouterHint, true)
})

test('OpenWrt LAN discovery excludes Transmission from controller ports', () => {
  assert.equal(
    isLikelyClashControllerResultForTesting({
      status: 401,
      headers: {
        server: 'Transmission',
        'www-authenticate': 'Basic realm="Transmission"',
      },
      text: '',
    }),
    false,
  )

  assert.equal(
    isLikelyClashControllerResultForTesting({
      status: 401,
      headers: {
        vary: 'Origin',
      },
      text: '',
    }),
    true,
  )
})

test('OpenWrt LAN discovery requires confirmed OpenWrt web signal', () => {
  assert.equal(
    shouldIncludeOpenWrtCandidateForTesting({
      hasOpenWrtHint: false,
      controllerOpen: true,
      score: 40,
    }),
    false,
  )

  assert.equal(
    shouldIncludeOpenWrtCandidateForTesting({
      hasOpenWrtHint: true,
      controllerOpen: false,
      score: 88,
    }),
    true,
  )
})

test('custom rule public URL replaces loopback host with matching LAN address', () => {
  assert.equal(
    buildPublicCustomRuleUrlForTesting({
      protocol: 'http',
      hostHeader: '127.0.0.1:2048',
      fileName: 'ziyong.list',
      openWrtHost: '10.0.0.18',
      localAddresses: ['192.168.3.88', '10.0.0.11'],
    }),
    'http://10.0.0.11:2048/ziyong.list',
  )

  assert.equal(
    buildPublicCustomRuleUrlForTesting({
      protocol: 'http',
      hostHeader: '10.0.0.11:2048',
      fileName: 'ziyong.list',
      openWrtHost: '10.0.0.18',
      localAddresses: ['10.0.0.11'],
    }),
    'http://10.0.0.11:2048/ziyong.list',
  )
})

test('custom rule public URL does not expose Docker bridge address', () => {
  assert.equal(
    buildPublicCustomRuleUrlForTesting({
      protocol: 'http',
      hostHeader: '127.0.0.1:2048',
      fileName: 'ziyong.list',
      openWrtHost: '10.0.0.18',
      localAddresses: ['172.17.0.2'],
    }),
    'http://127.0.0.1:2048/ziyong.list',
  )
})

test('OpenWrt SSH connection reveals the Docker host LAN address', () => {
  assert.equal(
    extractOpenWrtVisibleClientIpv4ForTesting('10.0.0.11 51842 10.0.0.18 22'),
    '10.0.0.11',
  )
  assert.equal(extractOpenWrtVisibleClientIpv4ForTesting('172.17.0.2 51842 10.0.0.18 22'), '')
  assert.equal(extractOpenWrtVisibleClientIpv4ForTesting('54.208.73.48 51842 10.0.0.18 22'), '')
})

test('custom rule YAML apply inserts provider, rule and proxy group without duplicates', () => {
  const source = `default: &default
  type: select
  proxies:
    - 直连

proxy-groups:
  - {name: AI, <<: *default}
  - {name: Test, <<: *default}

rules:
  - RULE-SET,TEST / Domain,Test
  - MATCH,其他

provider-class:
  class: &class {type: http, interval: 86400, behavior: classical, format: text}

rule-providers:
  TEST / Domain: {<<: *class, url: "https://example.test/Check.list"}
`

  const first = applyCustomRuleProviderToYamlContentForTesting(source, {
    providerName: 'LuFei / Custom',
    directProviderName: 'LuFei / Custom Direct',
    policyGroup: '路飞',
    directPolicyGroup: '路飞直连',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
    directRuleUrl: 'http://10.0.0.10:2048/ziyong-direct.list',
  })

  assert.equal(first.changed, true)
  assert.equal(first.addedProvider, true)
  assert.equal(first.addedRule, true)
  assert.equal(first.addedProxyGroup, true)
  assert.match(
    first.content,
    /  LuFei \/ Custom: \{<<: \*class, url: "http:\/\/10\.0\.0\.10:2048\/ziyong\.list"\}/,
  )
  assert.match(
    first.content,
    /  LuFei \/ Custom Direct: \{<<: \*class, url: "http:\/\/10\.0\.0\.10:2048\/ziyong-direct\.list"\}/,
  )
  assert.match(
    first.content,
    /  - \{name: 路飞, <<: \*default\}\n  - \{name: 路飞直连, <<: \*default\}\n  - \{name: AI, <<: \*default\}/,
  )
  assert.match(
    first.content,
    /  - RULE-SET,LuFei \/ Custom,路飞\n  - RULE-SET,LuFei \/ Custom Direct,路飞直连\n  - RULE-SET,TEST \/ Domain,Test/,
  )
  assert.match(
    first.content,
    /  LuFei \/ Custom: \{<<: \*class, url: "http:\/\/10\.0\.0\.10:2048\/ziyong\.list"\}\n  LuFei \/ Custom Direct: \{<<: \*class, url: "http:\/\/10\.0\.0\.10:2048\/ziyong-direct\.list"\}\n  TEST \/ Domain:/,
  )
  assert.match(first.content, /  - \{name: 路飞, <<: \*default\}/)
  assert.match(first.content, /  - \{name: 路飞直连, <<: \*default\}/)

  const second = applyCustomRuleProviderToYamlContentForTesting(first.content, {
    providerName: 'LuFei / Custom',
    directProviderName: 'LuFei / Custom Direct',
    policyGroup: '路飞',
    directPolicyGroup: '路飞直连',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
    directRuleUrl: 'http://10.0.0.10:2048/ziyong-direct.list',
  })

  assert.equal(second.changed, false)
  assert.equal(second.content, first.content)
})

test('custom rule YAML backup keeps one latest LuFei backup', () => {
  const configPath = '/etc/openclash/config/lufei.yaml'
  const backupPath = getRemoteYamlBackupPathForTesting(configPath)
  const cleanupCommand = getRemoteYamlBackupCleanupCommandForTesting(configPath, backupPath)

  assert.equal(backupPath, '/etc/openclash/config/lufei.yaml.lufei-latest.bak')
  assert.match(cleanupCommand, /find '\/etc\/openclash\/config'/)
  assert.match(cleanupCommand, /-name 'lufei\.yaml\.lufei-\*\.bak'/)
  assert.match(cleanupCommand, /! -name 'lufei\.yaml\.lufei-latest\.bak'/)
  assert.match(cleanupCommand, /-exec rm -f \{\} \+/)
})

test('custom rule YAML apply updates old single custom provider to proxy and direct providers', () => {
  const source = `default: &default
  type: select
  proxies:
    - DIRECT

proxy-groups:
  - {name: 自定义-代理, <<: *default}

rules:
  - RULE-SET,LuFei / Custom,自定义-代理
  - MATCH,DIRECT

provider-class:
  class: &class {type: http, interval: 86400, behavior: classical, format: text}

rule-providers:
  LuFei / Custom: {<<: *class, url: "http://old-host:2048/ziyong.list"}
`

  const first = applyCustomRuleProviderToYamlContentForTesting(source, {
    providerName: 'LuFei / Custom',
    directProviderName: 'LuFei / Custom Direct',
    policyGroup: '自定义-代理',
    directPolicyGroup: '自定义-直连',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
    directRuleUrl: 'http://10.0.0.10:2048/ziyong-direct.list',
  })

  assert.equal(first.changed, true)
  assert.equal(first.addedProvider, true)
  assert.equal(first.updatedProvider, true)
  assert.equal(first.addedRule, true)
  assert.equal(first.addedProxyGroup, true)
  assert.doesNotMatch(first.content, /old-host/)
  assert.match(
    first.content,
    /  LuFei \/ Custom: \{<<: \*class, url: "http:\/\/10\.0\.0\.10:2048\/ziyong\.list"\}/,
  )
  assert.match(
    first.content,
    /  LuFei \/ Custom Direct: \{<<: \*class, url: "http:\/\/10\.0\.0\.10:2048\/ziyong-direct\.list"\}/,
  )
  assert.match(first.content, /  - RULE-SET,LuFei \/ Custom,自定义-代理/)
  assert.match(first.content, /  - RULE-SET,LuFei \/ Custom Direct,自定义-直连/)
  assert.match(first.content, /  - \{name: 自定义-直连, <<: \*default\}/)

  const second = applyCustomRuleProviderToYamlContentForTesting(first.content, {
    providerName: 'LuFei / Custom',
    directProviderName: 'LuFei / Custom Direct',
    policyGroup: '自定义-代理',
    directPolicyGroup: '自定义-直连',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
    directRuleUrl: 'http://10.0.0.10:2048/ziyong-direct.list',
  })

  assert.equal(second.changed, false)
  assert.equal(second.content, first.content)
})

test('custom rule YAML apply removes legacy single custom policy group', () => {
  const source = `default: &default
  type: select
  proxies:
    - DIRECT

proxy-groups:
  - {name: 自定义-直连, type: select, proxies: [DIRECT]}
  - {name: 自定义-代理, <<: *default}
  - {name: 自定义, <<: *default}

rules:
  - RULE-SET,LuFei / Custom,自定义
  - MATCH,DIRECT

provider-class:
  class: &class {type: http, interval: 86400, behavior: classical, format: text}

rule-providers:
  LuFei / Custom: {<<: *class, url: "http://old-host:2048/ziyong.list"}
`

  const result = applyCustomRuleProviderToYamlContentForTesting(source, {
    providerName: 'LuFei / Custom',
    directProviderName: 'LuFei / Custom Direct',
    policyGroup: '自定义-代理',
    directPolicyGroup: '自定义-直连',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
    directRuleUrl: 'http://10.0.0.10:2048/ziyong-direct.list',
  })

  assert.equal(result.changed, true)
  assert.equal(result.removedLegacyProxyGroups, 1)
  assert.equal(result.removedLegacyRules, 1)
  assert.equal(result.updatedProxyGroup, true)
  assert.doesNotMatch(result.content, /\{name: 自定义, <<: \*default\}/)
  assert.doesNotMatch(result.content, /RULE-SET,LuFei \/ Custom,自定义\n/)
  assert.match(result.content, /\{name: 自定义-代理, <<: \*default\}/)
  assert.match(result.content, /\{name: 自定义-直连, <<: \*default\}/)
  assert.match(result.content, /RULE-SET,LuFei \/ Custom,自定义-代理/)
  assert.match(result.content, /RULE-SET,LuFei \/ Custom Direct,自定义-直连/)
})

test('custom rule YAML apply keeps proxy before direct in generated sections', () => {
  const source = `default: &default
  type: select
  proxies:
    - DIRECT

proxy-groups:
  - {name: 自定义-直连, type: select, proxies: [DIRECT]}
  - {name: 自定义-代理, <<: *default}
  - {name: AI, <<: *default}

rules:
  - RULE-SET,LuFei / Custom Direct,自定义-直连
  - RULE-SET,LuFei / Custom,自定义-代理
  - MATCH,DIRECT

provider-class:
  class: &class {type: http, interval: 86400, behavior: classical, format: text}

rule-providers:
  LuFei / Custom Direct: {<<: *class, url: "http://10.0.0.10:2048/ziyong-direct.list"}
  LuFei / Custom: {<<: *class, url: "http://10.0.0.10:2048/ziyong.list"}
`

  const result = applyCustomRuleProviderToYamlContentForTesting(source, {
    providerName: 'LuFei / Custom',
    directProviderName: 'LuFei / Custom Direct',
    policyGroup: '自定义-代理',
    directPolicyGroup: '自定义-直连',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
    directRuleUrl: 'http://10.0.0.10:2048/ziyong-direct.list',
  })

  assert.equal(result.changed, true)
  assert.equal(result.normalizedProxyGroupOrder, true)
  assert.equal(result.normalizedRuleOrder, true)
  assert.equal(result.normalizedProviderOrder, true)
  assert.equal(result.updatedProxyGroup, true)
  assert.match(
    result.content,
    /  - \{name: 自定义-代理, <<: \*default\}\n  - \{name: 自定义-直连, <<: \*default\}\n  - \{name: AI, <<: \*default\}/,
  )
  assert.match(
    result.content,
    /  - RULE-SET,LuFei \/ Custom,自定义-代理\n  - RULE-SET,LuFei \/ Custom Direct,自定义-直连\n  - MATCH,DIRECT/,
  )
  assert.match(
    result.content,
    /  LuFei \/ Custom: \{<<: \*class, url: "http:\/\/10\.0\.0\.10:2048\/ziyong\.list"\}\n  LuFei \/ Custom Direct: \{<<: \*class, url: "http:\/\/10\.0\.0\.10:2048\/ziyong-direct\.list"\}/,
  )
})

test('custom rule YAML apply prefers Hong Kong proxy when it exists in default group', () => {
  const source = `default: &default
  type: select
  proxies:
    - 直连
    - 所有-自动
    - 所有-手动
    - 香港-自动
    - 香港-故转
    - 日本-故转
    - 拒绝

proxy-groups:
  - {name: AI, <<: *default}

rules:
  - MATCH,其他

provider-class:
  class: &class {type: http, interval: 86400, behavior: classical, format: text}

rule-providers:
  TEST / Domain: {<<: *class, url: "https://example.test/Check.list"}
`

  const result = applyCustomRuleProviderToYamlContentForTesting(source, {
    providerName: 'LuFei / Custom',
    directProviderName: 'LuFei / Custom Direct',
    policyGroup: '自定义-代理',
    directPolicyGroup: '自定义-直连',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
    directRuleUrl: 'http://10.0.0.10:2048/ziyong-direct.list',
  })

  assert.match(
    result.content,
    /  - \{name: 自定义-代理, type: select, proxies: \["香港-自动", "直连", "所有-自动", "所有-手动", "香港-故转", "日本-故转", "拒绝"\]\}/,
  )
  assert.match(result.content, /  - \{name: 自定义-直连, <<: \*default\}/)
})

test('custom rule YAML apply removes stale custom provider policy references', () => {
  const source = `default: &default
  type: select
  proxies:
    - DIRECT

proxy-groups:
  - {name: 自定义-代理, <<: *default}
  - {name: 路飞, <<: *default}

rules:
  - RULE-SET,LuFei / Custom,路飞
  - RULE-SET,LuFei / Custom Direct,旧直连
  - RULE-SET,GitHub / Domain,GitHub
  - MATCH,其他

provider-class:
  class: &class {type: http, interval: 86400, behavior: classical, format: text}

rule-providers:
  LuFei / Custom: {<<: *class, url: "http://10.0.0.10:2048/ziyong.list"}
  LuFei / Custom Direct: {<<: *class, url: "http://10.0.0.10:2048/ziyong-direct.list"}
  GitHub / Domain: {<<: *class, url: "https://example.test/github.list"}
`

  const result = applyCustomRuleProviderToYamlContentForTesting(source, {
    providerName: 'LuFei / Custom',
    directProviderName: 'LuFei / Custom Direct',
    policyGroup: '自定义-代理',
    directPolicyGroup: '自定义-直连',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
    directRuleUrl: 'http://10.0.0.10:2048/ziyong-direct.list',
  })

  assert.equal(result.removedStaleProviderRules, 2)
  assert.doesNotMatch(result.content, /RULE-SET,LuFei \/ Custom,路飞/)
  assert.doesNotMatch(result.content, /RULE-SET,LuFei \/ Custom Direct,旧直连/)
  assert.match(
    result.content,
    /  - RULE-SET,LuFei \/ Custom,自定义-代理\n  - RULE-SET,LuFei \/ Custom Direct,自定义-直连\n  - RULE-SET,GitHub \/ Domain,GitHub/,
  )
})

test('custom rule YAML apply removes duplicate custom proxy groups', () => {
  const source = `default: &default
  type: select
  proxies:
    - DIRECT

proxy-groups:
  - {name: AI, <<: *default}
  - {name: 路飞, <<: *default}
  - {name: 路飞, <<: *default}
  - name: 路飞
    type: select
    proxies:
      - DIRECT

rules:
  - RULE-SET,LuFei / Custom,路飞
  - MATCH,DIRECT

rule-providers:
  LuFei / Custom: {type: http, url: "http://10.0.0.10:2048/ziyong.list"}
`

  const result = applyCustomRuleProviderToYamlContentForTesting(source, {
    providerName: 'LuFei / Custom',
    policyGroup: '路飞',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
  })

  assert.equal(result.changed, true)
  assert.equal(result.removedDuplicateProxyGroups, 2)
  assert.equal((result.content.match(/name:\s*路飞/g) || []).length, 1)
})

test('custom rule YAML apply avoids proxy provider name conflict', () => {
  const source = `proxy-providers:
  路飞:
    type: http
    url: "https://example.test/proxies.yaml"

default: &default
  type: select
  proxies:
    - DIRECT

proxy-groups:
  - {name: 路飞, <<: *default}
  - {name: AI, <<: *default}

rules:
  - RULE-SET,LuFei / Custom,路飞
  - MATCH,DIRECT

rule-providers:
  LuFei / Custom: {type: http, url: "http://10.0.0.10:2048/ziyong.list"}
`

  const result = applyCustomRuleProviderToYamlContentForTesting(source, {
    providerName: 'LuFei / Custom',
    policyGroup: '路飞',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
  })

  assert.equal(result.changed, true)
  assert.equal(result.policyGroup, '自定义-代理')
  assert.equal(result.removedConflictingProxyGroups, 1)
  assert.doesNotMatch(result.content, /\{name: 路飞, <<: \*default\}/)
  assert.match(result.content, /\{name: 自定义-代理, <<: \*default\}/)
  assert.match(result.content, /RULE-SET,LuFei \/ Custom,自定义-代理/)
  assert.doesNotMatch(result.content, /RULE-SET,LuFei \/ Custom,路飞/)
})

test('custom rules manager generates rules and snippets', () => {
  replaceSnapshot({})

  assert.deepEqual(readCustomRulesSettings(), {
    providerName: 'LuFei / Custom',
    directProviderName: 'LuFei / Custom Direct',
    policyGroup: '自定义-代理',
    directPolicyGroup: '自定义-直连',
    fileName: 'ziyong.list',
    directFileName: 'ziyong-direct.list',
  })

  assert.equal(makeCustomRule('Example.COM'), 'DOMAIN-SUFFIX,example.com')
  assert.equal(makeCustomRule('https://api.example.com/path'), 'DOMAIN-SUFFIX,api.example.com')
  assert.equal(makeCustomRule('1.2.3.4'), 'IP-CIDR,1.2.3.4/32,no-resolve')
  assert.equal(makeCustomRule('10.0.0.0/8'), 'IP-CIDR,10.0.0.0/8,no-resolve')

  const first = addCustomRule({ target: 'example.com', policy: 'proxy' })
  const second = addCustomRule({ target: 'https://example.com/a', policy: 'proxy' })
  const direct = addCustomRule({ target: 'www.baidu.com', policy: 'direct' })
  addCustomRule({ target: '1.2.3.4', policy: 'proxy' })

  assert.equal(first.added, true)
  assert.equal(second.added, false)
  assert.equal(direct.added, true)
  assert.deepEqual(readCustomRules('proxy'), [
    'DOMAIN-SUFFIX,example.com',
    'IP-CIDR,1.2.3.4/32,no-resolve',
  ])
  assert.deepEqual(readCustomRules('direct'), ['DOMAIN-SUFFIX,www.baidu.com'])
  assert.equal(
    readCustomRuleListText('proxy'),
    'DOMAIN-SUFFIX,example.com\nIP-CIDR,1.2.3.4/32,no-resolve\n',
  )
  assert.equal(readCustomRuleListText('direct'), 'DOMAIN-SUFFIX,www.baidu.com\n')

  updateCustomRulesSettings({ policyGroup: 'lufei' })
  assert.equal(readCustomRulesSettings().policyGroup, 'lufei')
  assert.equal(readCustomRulesSettings().directPolicyGroup, '自定义-直连')
  assert.equal(
    buildCustomRuleSnippets(
      'http://10.0.0.10:2048/ziyong.list',
      'http://10.0.0.10:2048/ziyong-direct.list',
    ).ruleLine,
    'RULE-SET,LuFei / Custom,lufei\nRULE-SET,LuFei / Custom Direct,自定义-直连',
  )
  assert.match(
    buildCustomRuleSnippets(
      'http://10.0.0.10:2048/ziyong.list',
      'http://10.0.0.10:2048/ziyong-direct.list',
    ).proxyGroupLine,
    /name: lufei, <<: \*default/,
  )
  assert.match(
    buildCustomRuleSnippets(
      'http://10.0.0.10:2048/ziyong.list',
      'http://10.0.0.10:2048/ziyong-direct.list',
    ).proxyGroupLine,
    /name: 自定义-直连, <<: \*default/,
  )
})

test('custom rules manager adds batch raw rules and plain targets', () => {
  replaceSnapshot({})

  const batch = addCustomRules({
    targets: `DOMAIN-KEYWORD,m-team
DOMAIN-KEYWORD,nicept
DOMAIN-SUFFIX,cnboy.org
bookmarkearth.com
1.1.1.1`,
    kind: 'auto',
    policy: 'proxy',
  })

  assert.equal(batch.addedCount, 5)
  assert.equal(batch.errorCount, 0)
  assert.deepEqual(
    batch.results.map((item) => item.rule),
    [
      'DOMAIN-KEYWORD,m-team',
      'DOMAIN-KEYWORD,nicept',
      'DOMAIN-SUFFIX,cnboy.org',
      'DOMAIN-SUFFIX,bookmarkearth.com',
      'IP-CIDR,1.1.1.1/32,no-resolve',
    ],
  )
  assert.match(readCustomRuleListText('proxy'), /DOMAIN-KEYWORD,m-team/)
  assert.match(readCustomRuleListText('proxy'), /DOMAIN-SUFFIX,bookmarkearth\.com/)
})

test('custom rules text editor preserves comments and normalizes plain domains', () => {
  replaceSnapshot({})

  const result = replaceCustomRulesTextForTesting({
    policy: 'proxy',
    text: `# PT
DOMAIN-KEYWORD,m-team
cnboy.org

# DNS
IP-CIDR,8.8.8.8/32,no-resolve`,
  })

  assert.equal(result.updatedCount, 3)
  assert.equal(result.commentCount, 2)
  assert.deepEqual(readCustomRules('proxy'), [
    '# PT',
    'DOMAIN-KEYWORD,m-team',
    'DOMAIN-SUFFIX,cnboy.org',
    '# DNS',
    'IP-CIDR,8.8.8.8/32,no-resolve',
  ])
  assert.equal(
    readCustomRuleListText('proxy'),
    '# PT\nDOMAIN-KEYWORD,m-team\nDOMAIN-SUFFIX,cnboy.org\n# DNS\nIP-CIDR,8.8.8.8/32,no-resolve\n',
  )
})

test('custom rules manager keeps pasted clash rules as separate entries', () => {
  replaceSnapshot({})

  const pastedRules = `DOMAIN-KEYWORD,m-team
DOMAIN-KEYWORD,nicept
DOMAIN-KEYWORD,ilolicon
DOMAIN-KEYWORD,hdatmos
DOMAIN-KEYWORD,52pt
DOMAIN-KEYWORD,hdupt
DOMAIN-KEYWORD,carpt
DOMAIN-KEYWORD,hddolby
DOMAIN-KEYWORD,btschool
DOMAIN-KEYWORD,hdtime
DOMAIN-KEYWORD,hdhome
DOMAIN-KEYWORD,rousi
DOMAIN-KEYWORD,cyanbug
DOMAIN-KEYWORD,hdkyl
DOMAIN-KEYWORD,0ff
DOMAIN-KEYWORD,hdarea
DOMAIN-KEYWORD,piggo
DOMAIN-KEYWORD,tu88
DOMAIN-KEYWORD,ptvicomo
DOMAIN-KEYWORD,keepfrds
DOMAIN-KEYWORD,pandapt
DOMAIN-KEYWORD,htpt
DOMAIN-SUFFIX,cnboy.org
DOMAIN-SUFFIX,bookmarkearth.com`
  const batch = addCustomRules({
    targets: pastedRules,
    kind: 'auto',
    policy: 'proxy',
  })
  const listLines = readCustomRuleListText('proxy').trim().split('\n')

  assert.equal(batch.addedCount, 24)
  assert.equal(batch.errorCount, 0)
  assert.equal(listLines.length, 24)
  assert.equal(listLines[0], 'DOMAIN-KEYWORD,m-team')
  assert.equal(listLines[23], 'DOMAIN-SUFFIX,bookmarkearth.com')
  assert.ok(!listLines.some((line) => line.includes('\n')))
})

test('custom rule providers are synced to local rule cache', async () => {
  replaceSnapshot({})
  addCustomRule({ target: 'example-cache.com', policy: 'proxy' })
  addCustomRule({ target: 'direct-cache.com', policy: 'direct' })

  const syncResult = syncCustomRuleProvidersToCacheForTesting({
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
    directRuleUrl: 'http://10.0.0.10:2048/ziyong-direct.list',
  })

  assert.deepEqual(syncResult.syncedProviders, ['LuFei / Custom', 'LuFei / Custom Direct'])
  assert.equal(syncResult.providerCounts['LuFei / Custom'], 1)
  assert.equal(syncResult.providerCounts['LuFei / Custom Direct'], 1)

  const proxySearch = await searchRuleProviderCache('example-cache.com', {
    providerNames: ['LuFei / Custom'],
  })
  const directSearch = await searchRuleProviderCache('direct-cache.com', {
    providerNames: ['LuFei / Custom Direct'],
  })

  assert.equal(proxySearch.matches[0]?.name, 'LuFei / Custom')
  assert.equal(directSearch.matches[0]?.name, 'LuFei / Custom Direct')
})

test('custom rule changes keep one latest file backup in data directory', async () => {
  replaceSnapshot({})
  const backupDir = path.join(tempDir, 'custom-rule-backups')
  await fs.rm(backupDir, { recursive: true, force: true })

  const added = addCustomRule({ target: 'backup-check.example', policy: 'proxy' })

  assert.equal(added.added, true)
  assert.deepEqual((await fs.readdir(backupDir)).sort(), ['latest-non-empty.json', 'latest.json'])

  const deleted = deleteCustomRuleForTesting(added.rule, 'proxy')

  assert.equal(deleted.removed, true)
  assert.deepEqual((await fs.readdir(backupDir)).sort(), ['latest-non-empty.json', 'latest.json'])
})

test('custom rules restore from latest backup when storage is empty', async () => {
  replaceSnapshot({})
  const backupDir = path.join(tempDir, 'custom-rule-backups')
  await fs.rm(backupDir, { recursive: true, force: true })

  addCustomRule({ target: 'restore-check.example', policy: 'proxy' })
  updateCustomRulesSettings({ policyGroup: 'restored-group' })

  replaceSnapshot({})

  assert.deepEqual(readCustomRules('proxy'), [])
  assert.equal(restoreCustomRulesFromBackupForTesting(), true)
  assert.deepEqual(readCustomRules('proxy'), ['DOMAIN-SUFFIX,restore-check.example'])
  assert.equal(readCustomRulesSettings().policyGroup, 'restored-group')
  assert.deepEqual((await fs.readdir(backupDir)).sort(), ['latest-non-empty.json', 'latest.json'])
})

test('managed settings import preserves custom rules', () => {
  replaceSnapshot({})

  addCustomRule({ target: 'preserve-import.example', policy: 'proxy' })

  replaceManagedSnapshotForTesting({
    'config/theme': 'dark',
    'setup/api-list': '[]',
  })

  assert.deepEqual(readCustomRules('proxy'), ['DOMAIN-SUFFIX,preserve-import.example'])
  assert.equal(readSnapshot()['config/theme'], 'dark')
})

test('proxy group penetration cache expires when provider cache changes', () => {
  seedRuleProviderCacheForTesting([
    {
      name: 'LuFei / Custom',
      behavior: 'classical',
      format: 'text',
      url: 'http://10.0.0.10:2048/ziyong.list',
      body: '',
    },
  ])

  const rules = [
    {
      type: 'RuleSet',
      payload: 'LuFei / Custom',
      proxy: '自定义-代理',
      index: 0,
    },
  ]
  const emptyEntry = getProxyGroupRulePenetrationCacheEntryForTesting({
    groupName: '自定义-代理',
    rules,
  })

  assert.equal(emptyEntry.items.length, 0)

  seedRuleProviderCacheForTesting([
    {
      name: 'LuFei / Custom',
      behavior: 'classical',
      format: 'text',
      url: 'http://10.0.0.10:2048/ziyong.list',
      body: 'DOMAIN-SUFFIX,example.com\n',
    },
  ])

  assert.throws(
    () =>
      getProxyGroupRulePenetrationCacheEntryForTesting({
        groupName: '自定义-代理',
        cacheKey: emptyEntry.cacheKey,
        rules,
      }),
    /cache expired/,
  )

  const refreshedEntry = getProxyGroupRulePenetrationCacheEntryForTesting({
    groupName: '自定义-代理',
    rules,
  })

  assert.equal(refreshedEntry.items.length, 1)
  assert.equal(refreshedEntry.items[0].content, 'example.com')
})
