import type { Entry } from './domain.ts'

export type Preview = 'image' | 'pdf' | 'video' | 'audio'

export interface ArtifactFile {
  readonly objectKey: string
  readonly mime: string
  readonly bytes: number
}

const INLINE_TEXT: ReadonlySet<string> = new Set(['text/html', 'text/markdown', 'text/plain'])

const SCRIPTABLE: ReadonlySet<string> = new Set([
  'text/html',
  'application/xhtml+xml',
  'image/svg+xml',
  'text/xml',
  'application/xml',
])

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'] as const

export const artifactFile = (entry: Entry): ArtifactFile | undefined =>
  entry.objectKey === null || entry.mime === null || entry.bytes === null
    ? undefined
    : { objectKey: entry.objectKey, mime: entry.mime, bytes: entry.bytes }

export const previewOf = (mime: string): Preview | undefined => {
  if (mime.startsWith('image/')) {
    return 'image'
  }

  if (mime === 'application/pdf') {
    return 'pdf'
  }

  if (mime.startsWith('video/')) {
    return 'video'
  }

  if (mime.startsWith('audio/')) {
    return 'audio'
  }

  return undefined
}

const baseMime = (mime: string) => mime.split(';')[0]?.trim().toLowerCase() ?? ''

export const opensInline = (mime: string): boolean =>
  previewOf(mime) !== undefined || INLINE_TEXT.has(baseMime(mime))

export const runsScripts = (mime: string): boolean => SCRIPTABLE.has(baseMime(mime))

export const contentDisposition = (mime: string, name: string, download: boolean): string =>
  `${download || !opensInline(mime) ? 'attachment' : 'inline'}; filename*=UTF-8''${encodeURIComponent(name)}`

export const formatBytes = (bytes: number): string => {
  let value = bytes
  let unit = 0

  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024
    unit += 1
  }

  return `${value.toFixed(unit > 0 && value < 10 ? 1 : 0)} ${UNITS[unit]}`
}
