import { describe, expect, it } from 'vitest'
import { BYPASS_DNS_PRESET, validateDNSYAML } from './dns-yaml'

describe('validateDNSYAML', () => {
  it('accepts the bypass preset', () => {
    expect(validateDNSYAML(BYPASS_DNS_PRESET)).toBeNull()
  })

  it('accepts a dns: prefixed block', () => {
    expect(validateDNSYAML('dns:\n  enable: true\n  listen: "0.0.0.0:53"\n')).toBeNull()
  })

  it('rejects unknown keys', () => {
    expect(validateDNSYAML('enable: true\nbogus: 1\n')).toContain('不支持的键')
  })

  it('rejects invalid YAML', () => {
    expect(validateDNSYAML('enable: [\n')).toContain('DNS YAML 无效')
  })

  it('rejects inline dns', () => {
    expect(validateDNSYAML('dns: { enable: true }')).toContain('行内写法')
  })
})