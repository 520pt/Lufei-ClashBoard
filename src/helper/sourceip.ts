import { sourceIPLabelList } from '@/store/settings'
import { activeBackend } from '@/store/setup'
import * as ipaddr from 'ipaddr.js'
import { watch } from 'vue'

const CACHE_SIZE = 256
const ipLabelCache = new Map<string, string>()
const sourceIPMap = new Map<string, string>()
const sourceIPRegexList: { regex: RegExp; label: string }[] = []
type CIDREntry = { cidr: [ipaddr.IPv4 | ipaddr.IPv6, number]; label: string }
const sourceIPCIDRList: CIDREntry[] = []

const preprocessSourceIPList = () => {
  ipLabelCache.clear()
  sourceIPMap.clear()
  sourceIPRegexList.length = 0
  sourceIPCIDRList.length = 0

  for (const { key, label, scope } of sourceIPLabelList.value) {
    if (scope && !scope.includes(activeBackend.value?.uuid as string)) {
      continue
    }

    if (key.startsWith('/')) {
      sourceIPRegexList.push({ regex: new RegExp(key.slice(1), 'i'), label })
      continue
    }

    if (key.includes('/')) {
      try {
        const cidr = ipaddr.parseCIDR(key)
        sourceIPCIDRList.push({ cidr, label })
        continue
      } catch {
        // 无效 CIDR，忽略
      }
    }

    sourceIPMap.set(key, label)
  }
}

const cacheResult = (ip: string, label: string) => {
  ipLabelCache.set(ip, label)

  if (ipLabelCache.size > CACHE_SIZE) {
    const firstKey = ipLabelCache.keys().next().value

    if (firstKey) {
      ipLabelCache.delete(firstKey)
    }
  }

  return label
}

const isIPMatchingCIDR = (addr: ipaddr.IPv4 | ipaddr.IPv6, cidr: CIDREntry['cidr']) => {
  const [range, bits] = cidr

  if (addr.kind() === 'ipv4' && range.kind() === 'ipv4') {
    return (addr as ipaddr.IPv4).match(range as ipaddr.IPv4, bits)
  }

  if (addr.kind() === 'ipv6' && range.kind() === 'ipv6') {
    return (addr as ipaddr.IPv6).match(range as ipaddr.IPv6, bits)
  }

  return false
}

watch(() => [sourceIPLabelList.value, activeBackend.value], preprocessSourceIPList, {
  immediate: true,
  deep: true,
})

export const getIPLabelFromMap = (ip: string) => {
  if (!ip) return ip === '' ? 'Inner' : ''

  if (ipLabelCache.has(ip)) {
    return ipLabelCache.get(ip)!
  }
  const addr = ipaddr.parse(ip)
  const isIPv6 = addr.kind() === 'ipv6'

  if (isIPv6) {
    for (const [key, label] of sourceIPMap.entries()) {
      if (ip.endsWith(key)) {
        return cacheResult(ip, label)
      }
    }
  }

  if (sourceIPMap.has(ip)) {
    return cacheResult(ip, sourceIPMap.get(ip)!)
  }

  for (const { regex, label } of sourceIPRegexList) {
    if (regex.test(ip)) {
      return cacheResult(ip, label)
    }
  }

  for (const { cidr, label } of sourceIPCIDRList) {
    if (isIPMatchingCIDR(addr, cidr)) {
      return cacheResult(ip, label)
    }
  }

  return cacheResult(ip, ip)
}
