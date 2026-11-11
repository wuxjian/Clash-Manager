import { parseDocument } from 'yaml'

const dnsKeys = new Set([
  'enable', 'listen', 'ipv6', 'enhanced-mode', 'fake-ip-range', 'fake-ip-range6',
  'fake-ip-filter-mode', 'fake-ip-filter', 'prefer-h3', 'respect-rules', 'use-hosts',
  'use-system-hosts', 'default-nameserver', 'nameserver', 'fallback', 'fallback-filter',
  'nameserver-policy', 'proxy-server-nameserver', 'direct-nameserver',
  'direct-nameserver-follow-policy', 'cache-algorithm', 'cache-size', 'serve-stale', 'max-fails',
])

// BYPASS_DNS_PRESET is the recommended side-router DNS setup: listen on all
// interfaces so LAN clients can use the NAS directly, resolve domestic names
// over DoH, and send non-CN results through the proxy.
export const BYPASS_DNS_PRESET = `enable: true
listen: "0.0.0.0:53"
ipv6: false
enhanced-mode: "redir-host"
respect-rules: true

default-nameserver:
  - "223.5.5.5"
  - "119.29.29.29"
  - "114.114.114.114"

nameserver:
  - "https://doh.pub/dns-query"
  - "https://dns.alidns.com/dns-query"

fallback:
  - "https://1.1.1.1/dns-query"
  - "https://8.8.8.8/dns-query"

fallback-filter:
  geoip: true
  geoip-code: "CN"
  ipcidr:
    - "240.0.0.0/4"
    - "0.0.0.0/32"

nameserver-policy:
  "geosite:cn":
    - "https://doh.pub/dns-query"
    - "223.5.5.5"

proxy-server-nameserver:
  - "https://doh.pub/dns-query"
  - "https://dns.alidns.com/dns-query"
  - "tls://1.1.1.1"
  - "223.5.5.5"
`

// validateDNSYAML mirrors the helper's validation so obvious mistakes are
// reported before the configuration transaction starts.
export function validateDNSYAML(value: string): string | null {
  const text = value.trim()
  if (!text) return 'DNS YAML 不能为空'
  let body = text
  if (body.startsWith('dns:')) {
    const first = body.split('\n')[0] || ''
    if (first.replace(/^dns:/, '').trim()) return 'DNS YAML 不支持行内写法，请使用块状写法'
    body = body.split('\n').slice(1).map(line => line.replace(/^ {2}/, '')).join('\n')
  }
  const document = parseDocument(body)
  if (document.errors.length) return `DNS YAML 无效: ${document.errors[0]?.message || '未知错误'}`
  const parsed = document.toJS()
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return 'DNS YAML 必须是对象'
  const unknown = Object.keys(parsed).filter(key => !dnsKeys.has(key))
  if (unknown.length) return `DNS YAML 包含不支持的键: ${unknown.join(', ')}`
  return null
}