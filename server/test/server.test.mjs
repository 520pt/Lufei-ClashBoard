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
  applyCustomRuleProviderToYamlContentForTesting,
  buildPublicCustomRuleUrlForTesting,
  buildCustomRuleSnippets,
  clashControllerDiscoveryPortsForTesting,
  createAccessSessionTokenForTesting,
  extractNikkiYamlConfigPathsFromProcessListForTesting,
  extractRemoteYamlConfigPathsFromTextForTesting,
  extractRemoteYamlConfigPathsFromUciForTesting,
  getOpenWrtDiscoveryConcurrencyForTesting,
  getOpenWrtHttpSignalsForTesting,
  getOpenWrtLanScanTargetsForTesting,
  getOpenWrtLanScanTargetsFromSubnetForTesting,
  getRequestAccessAuthStatusForTesting,
  isLikelyClashControllerResultForTesting,
  makeCustomRule,
  readCustomRuleListText,
  readCustomRules,
  readCustomRulesSettings,
  replaceSnapshot,
  resolveOpenClashConfigPathFromUciForTesting,
  searchRuleProviderCache,
  seedRuleProviderCacheForTesting,
  shouldIncludeOpenWrtCandidateForTesting,
  shutdownServer,
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
    policyGroup: '路飞',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
  })

  assert.equal(first.changed, true)
  assert.equal(first.addedProvider, true)
  assert.equal(first.addedRule, true)
  assert.equal(first.addedProxyGroup, true)
  assert.match(
    first.content,
    /  LuFei \/ Custom: \{<<: \*class, url: "http:\/\/10\.0\.0\.10:2048\/ziyong\.list"\}/,
  )
  assert.match(first.content, /  - RULE-SET,LuFei \/ Custom,路飞\n  - RULE-SET,TEST \/ Domain,Test/)
  assert.match(first.content, /  - \{name: 路飞, <<: \*default\}/)

  const second = applyCustomRuleProviderToYamlContentForTesting(first.content, {
    providerName: 'LuFei / Custom',
    policyGroup: '路飞',
    ruleUrl: 'http://10.0.0.10:2048/ziyong.list',
  })

  assert.equal(second.changed, false)
  assert.equal(second.content, first.content)
})

test('custom rules manager generates rules and snippets', () => {
  replaceSnapshot({})

  assert.deepEqual(readCustomRulesSettings(), {
    providerName: 'LuFei / Custom',
    policyGroup: '路飞',
    fileName: 'ziyong.list',
  })

  assert.equal(makeCustomRule('Example.COM'), 'DOMAIN-SUFFIX,example.com')
  assert.equal(makeCustomRule('https://api.example.com/path'), 'DOMAIN-SUFFIX,api.example.com')
  assert.equal(makeCustomRule('1.2.3.4'), 'IP-CIDR,1.2.3.4/32,no-resolve')
  assert.equal(makeCustomRule('10.0.0.0/8'), 'IP-CIDR,10.0.0.0/8,no-resolve')

  const first = addCustomRule({ target: 'example.com' })
  const second = addCustomRule({ target: 'https://example.com/a' })
  addCustomRule({ target: '1.2.3.4' })

  assert.equal(first.added, true)
  assert.equal(second.added, false)
  assert.deepEqual(readCustomRules(), [
    'DOMAIN-SUFFIX,example.com',
    'IP-CIDR,1.2.3.4/32,no-resolve',
  ])
  assert.equal(
    readCustomRuleListText(),
    'DOMAIN-SUFFIX,example.com\nIP-CIDR,1.2.3.4/32,no-resolve\n',
  )

  updateCustomRulesSettings({ policyGroup: 'lufei' })
  assert.equal(readCustomRulesSettings().policyGroup, 'lufei')
  assert.equal(
    buildCustomRuleSnippets('http://10.0.0.10:2048/ziyong.list').ruleLine,
    'RULE-SET,LuFei / Custom,lufei',
  )
})
