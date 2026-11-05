import { describe, it, expect } from 'vitest'
import { sectionOf, NAV } from './nav'
import { isAlerting, sevKey, isKill, isDeny, actLabel, fmtBytes, fmtNum, clock, type Workload } from './api'

describe('nav', () => {
  it('maps a leaf page to its owning section', () => {
    expect(sectionOf('coverage').key).toBe('system')
    expect(sectionOf('triage').key).toBe('threats')
    expect(sectionOf('lateral').key).toBe('analysis')
  })
  it('falls back to the first section for an unknown page', () => {
    expect(sectionOf('nope' as never).key).toBe(NAV[0].key)
  })
})

describe('isAlerting', () => {
  const wl = (state: string): Workload => ({ state }) as Workload
  it('flags only real threat states', () => {
    for (const s of ['suspicious', 'escalating', 'breakout_imminent', 'compromised', 'memfd_created', 'stdio_redirected'])
      expect(isAlerting(wl(s))).toBe(true)
  })
  it('treats normal and a bare connect as non-alerting', () => {
    expect(isAlerting(wl('normal'))).toBe(false)
    expect(isAlerting(wl('connected'))).toBe(false) // outbound connect alone is benign
  })
})

describe('severity + action helpers', () => {
  it('sevKey maps known severities and defaults to info', () => {
    expect(sevKey('crit')).toBeTruthy()
    expect(sevKey('')).toBe('info')
    expect(sevKey('bogus')).toBe('info')
  })
  it('isKill / isDeny are case-insensitive substring checks', () => {
    expect(isKill('KILL')).toBe(true)
    expect(isKill('observe')).toBe(false)
    expect(isDeny('would deny')).toBe(true)
    expect(isDeny('')).toBe(false)
  })
  it('actLabel distinguishes enforced from shadowed', () => {
    const enforced = actLabel('kill', true)
    const shadow = actLabel('kill', false)
    expect(enforced.text).not.toBe(shadow.text)
  })
})

describe('formatters', () => {
  it('fmtBytes is human-readable (KiB/MiB)', () => {
    expect(fmtBytes(1024)).toBe('1 KiB')
    expect(fmtBytes(1048576)).toBe('1 MiB')
  })
  it('fmtNum rounds with locale grouping', () => {
    expect(fmtNum(999)).toBe('999')
    expect(fmtNum(1500)).toBe((1500).toLocaleString())
    expect(fmtNum(NaN)).toBe('0')
  })
  it('clock renders a HH:MM:SS time', () => {
    expect(clock(Date.UTC(2026, 0, 1, 10, 20, 30))).toMatch(/^\d{2}:\d{2}:\d{2}$/)
  })
})
