import * as Config from 'effect/Config'
import * as DateTime from 'effect/DateTime'
import * as Effect from 'effect/Effect'
import * as Option from 'effect/Option'
import * as HttpServerRequest from 'effect/unstable/http/HttpServerRequest'

import { ZONE_HEADER } from './api.ts'

export const ZONE_COOKIE = 'tz'
export const UTC = DateTime.zoneMakeOffset(0)

export const requestZone = Effect.map(HttpServerRequest.HttpServerRequest, (request) =>
  Option.fromUndefinedOr(request.headers[ZONE_HEADER] ?? request.cookies[ZONE_COOKIE]).pipe(
    Option.flatMap(DateTime.zoneMakeNamed),
    Option.getOrElse((): DateTime.TimeZone => UTC),
  ),
)

const PublicOrigin = Config.option(Config.string('PUBLIC_ORIGIN'))

const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/u

export const requestOrigin = Effect.gen(function* () {
  const configured = yield* PublicOrigin

  if (Option.isSome(configured)) {
    return new URL(configured.value).origin
  }

  const request = yield* HttpServerRequest.HttpServerRequest
  const host = request.headers['host'] ?? 'localhost'
  const proto = request.headers['x-forwarded-proto'] ?? (LOCAL_HOST.test(host) ? 'http' : 'https')

  return `${proto}://${host}`
}).pipe(Effect.orDie)

export const requestClient = Effect.map(HttpServerRequest.HttpServerRequest, (request) => {
  const forwarded = request.headers['x-forwarded-for']?.split(',').at(-1)?.trim()

  return forwarded !== undefined && forwarded !== ''
    ? forwarded
    : Option.getOrElse(request.remoteAddress, () => 'unknown')
})

export const clock = (at: DateTime.Utc, zone: DateTime.TimeZone) =>
  DateTime.format(DateTime.setZone(at, zone), {
    locale: 'en-GB',
    hour: '2-digit',
    minute: '2-digit',
  })
