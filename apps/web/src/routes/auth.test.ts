import { describe, expect, test } from 'bun:test'

import { safeNext } from './auth.tsx'

describe('safeNext', () => {
  test('keeps a same-origin path with its query and hash', () => {
    expect(safeNext('/e/plan?share#top')).toBe('/e/plan?share#top')
  })

  test('falls back to / for anything that leaves the origin', () => {
    for (const next of [
      undefined,
      '',
      'https://evil.example',
      '//evil.example',
      '/\\evil.example',
      '/\t/evil.example',
      '/\n/evil.example',
      'javascript:alert(1)',
    ]) {
      expect(safeNext(next)).toBe('/')
    }
  })
})
