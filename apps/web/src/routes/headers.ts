import * as Effect from 'effect/Effect'
import * as HttpRouter from 'effect/unstable/http/HttpRouter'
import * as HttpServerResponse from 'effect/unstable/http/HttpServerResponse'

import { INLINE_SCRIPTS } from '../components/Layout.tsx'
import { ObjectStore } from '../services/ObjectStore.ts'

const scriptHash = (script: string) =>
  `'sha256-${new Bun.CryptoHasher('sha256').update(script).digest('base64')}'`

export const contentSecurityPolicy = (bucket: string) =>
  [
    "default-src 'self'",
    `script-src 'self' ${INLINE_SCRIPTS.map(scriptHash).join(' ')}`,
    "style-src 'self' 'unsafe-inline'",
    `img-src 'self' data: blob: ${bucket}`,
    `media-src 'self' blob: ${bucket}`,
    `frame-src 'self' ${bucket}`,
    `connect-src 'self' ${bucket}`,
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ')

export const securityHeaders = (bucket: string) => ({
  'content-security-policy': contentSecurityPolicy(bucket),
  'strict-transport-security': 'max-age=31536000',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
})

export const SecurityHeaders = HttpRouter.middleware(
  Effect.gen(function* () {
    const headers = securityHeaders((yield* ObjectStore).origin)

    return (handler) => Effect.map(handler, HttpServerResponse.setHeaders(headers))
  }),
  { global: true },
)
