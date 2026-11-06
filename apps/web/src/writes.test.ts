import { afterAll, afterEach, describe, expect, test } from 'bun:test'
import { BunHttpServer } from '@effect/platform-bun'
import * as ConfigProvider from 'effect/ConfigProvider'
import * as DateTime from 'effect/DateTime'
import * as Effect from 'effect/Effect'
import * as Layer from 'effect/Layer'
import * as ManagedRuntime from 'effect/ManagedRuntime'
import * as Aead from 'effect/crypto/Aead'
import * as CryptoError from 'effect/crypto/CryptoError'
import * as SecureRandom from 'effect/crypto/SecureRandom'
import * as HttpClient from 'effect/http/HttpClient'
import * as HttpClientRequest from 'effect/http/HttpClientRequest'
import * as HttpRouter from 'effect/http/HttpRouter'
import * as HttpApiClient from 'effect/http-api/HttpApiClient'

import { Api } from './api.ts'
import { entryRef, googleAccountId, SealFailed } from './domain.ts'
import { ApiRoutes } from './routes/api.ts'
import { SessionGate } from './routes/auth.tsx'
import { CalendarRoutes } from './routes/calendar.tsx'
import { EntriesRoutes } from './routes/entries.tsx'
import { Auth } from './services/Auth.ts'
import { Calendar } from './services/Calendar.ts'
import { Cipher } from './services/Cipher.ts'
import { DatabaseLayer } from './services/Database.ts'
import { Entries } from './services/Entries.ts'
import { Google } from './services/Google.ts'
import { Markdown } from './services/Markdown.ts'
import { ObjectStore } from './services/ObjectStore.ts'
import { ShareLinks } from './services/ShareLinks.ts'

const PASSWORD = Bun.randomUUIDv7()
const SERVER_ERROR = 500
const BAD_REQUEST = 400

const sealing = { refuse: false }

const RealAead = Aead.layerWebCrypto.pipe(Layer.provide(SecureRandom.layerWebCrypto))

const RefusingAead = Layer.effect(Aead.Aead)(
  Effect.gen(function* () {
    const real = yield* Aead.Aead

    return {
      ...real,
      encrypt: (key, plaintext, options) =>
        Effect.suspend(() =>
          sealing.refuse
            ? Effect.fail(
                new CryptoError.CryptoError({
                  module: 'Aead',
                  method: 'encrypt',
                  reason: new CryptoError.Unsupported({ description: 'refused by the test' }),
                }),
              )
            : real.encrypt(key, plaintext, options),
        ),
    } satisfies typeof Aead.Aead.Service
  }),
).pipe(Layer.provide(RealAead))

const CipherLayer = Cipher.layer.pipe(
  Layer.provide(Layer.mergeAll(RefusingAead, SecureRandom.layerWebCrypto)),
)

const FakeObjectStore = Layer.succeed(ObjectStore)({
  origin: 'https://bucket.test',
  newKey: Effect.succeed('artifacts/new'),
  uploadUrl: (key) => `https://bucket.test/${key}?put`,
  downloadUrl: (key) => `https://bucket.test/${key}?get`,
  remove: () => Effect.void,
  head: () => Effect.succeedSome({ mime: 'text/plain', bytes: 1 }),
  upload: () => Effect.die('unused'),
})

const FakeCalendar = Layer.succeed(Calendar)({
  accounts: Effect.succeed([]),
  connect: () => Effect.fail(new SealFailed()),
  disconnect: () => Effect.void,
  events: () =>
    Effect.map(DateTime.now, (now) => [
      {
        accountId: googleAccountId('account'),
        id: 'standup',
        title: 'Standup',
        start: now,
        end: DateTime.addDuration(now, '30 minutes'),
        attendees: [],
        link: undefined,
      },
    ]),
})

const TestConfig = ConfigProvider.layer(
  ConfigProvider.fromUnknown({
    PASSWORD_HASH: Bun.password.hashSync(PASSWORD),
    SESSION_SECRET: 'test-secret',
    ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64'),
    DATABASE_PATH: ':memory:',
  }),
)

const Storage = Layer.mergeAll(DatabaseLayer, CipherLayer, FakeObjectStore)

const Services = Layer.mergeAll(
  Auth.layer,
  Markdown.layer.pipe(Layer.provideMerge(Entries.layer)),
  ShareLinks.layer,
  FakeCalendar,
  Layer.mock(Google)({ authUrl: () => 'https://google.test/auth' }),
  SecureRandom.layerWebCrypto,
).pipe(Layer.provideMerge(Storage))

const Routes = Layer.mergeAll(ApiRoutes, EntriesRoutes, CalendarRoutes).pipe(
  Layer.provide(SessionGate),
)

const App = HttpRouter.serve(Routes, { disableListenLog: true, disableLogger: true }).pipe(
  Layer.provide(Services),
)

const TestServer = App.pipe(Layer.provideMerge(BunHttpServer.layerTest))

const runtime = ManagedRuntime.make(TestServer.pipe(Layer.provide(TestConfig)))

const run = <Success, Failure>(effect: Effect.Effect<Success, Failure, HttpClient.HttpClient>) =>
  runtime.runPromise(effect)

const session = Effect.gen(function* () {
  const anonymous = yield* HttpApiClient.make(Api)
  const { token } = yield* anonymous.auth.login({ payload: { password: PASSWORD } })
  const client = yield* HttpApiClient.make(Api, {
    transformClient: HttpClient.mapRequest(HttpClientRequest.bearerToken(token)),
  })
  const http = HttpClient.mapRequest(
    yield* HttpClient.HttpClient,
    HttpClientRequest.bearerToken(token),
  )

  return { client, http }
})

const refused = <Success, Failure, Services_>(effect: Effect.Effect<Success, Failure, Services_>) =>
  Effect.acquireUseRelease(
    Effect.sync(() => {
      sealing.refuse = true
    }),
    () => effect,
    () =>
      Effect.sync(() => {
        sealing.refuse = false
      }),
  )

afterEach(() => {
  sealing.refuse = false
})

afterAll(() => runtime.dispose())

describe('a failed seal over /api', () => {
  test('create answers SealFailed', () =>
    run(
      Effect.gen(function* () {
        const { client } = yield* session
        const error = yield* refused(
          Effect.flip(client.entries.create({ payload: { type: 'note', body: 'lost' } })),
        )

        expect(error).toBeInstanceOf(SealFailed)
      }),
    ))

  test('save answers SealFailed and the version stands', () =>
    run(
      Effect.gen(function* () {
        const { client } = yield* session
        const entry = yield* client.entries.create({ payload: { type: 'note', body: 'kept' } })
        const error = yield* refused(
          Effect.flip(
            client.entries.save({
              params: { id: entry.id },
              payload: { body: 'lost', version: entry.version },
            }),
          ),
        )
        const saved = yield* client.entries.save({
          params: { id: entry.id },
          payload: { body: 'saved', version: entry.version },
        })

        expect(error).toBeInstanceOf(SealFailed)
        expect(saved.version).toBe(entry.version + 1)
      }),
    ))

  test('a meeting start answers SealFailed', () =>
    run(
      Effect.gen(function* () {
        const { client } = yield* session
        const error = yield* refused(Effect.flip(client.meetings.start()))

        expect(error).toBeInstanceOf(SealFailed)
      }),
    ))

  test('an artifact register answers SealFailed', () =>
    run(
      Effect.gen(function* () {
        const { client } = yield* session
        const error = yield* refused(
          Effect.flip(
            client.artifacts.register({
              payload: { files: [{ key: 'artifacts/upload', title: Bun.randomUUIDv7() }] },
            }),
          ),
        )

        expect(error).toBeInstanceOf(SealFailed)
      }),
    ))
})

describe('two ticks on one task list at once', () => {
  test('both land', () =>
    run(
      Effect.gen(function* () {
        const { client, http } = yield* session
        const task = yield* client.entries.create({
          payload: { type: 'task', body: '- [ ] one\n- [ ] two\n- [ ] three\n- [ ] four' },
        })
        const responses = yield* Effect.forEach(
          [0, 1, 2, 3],
          (index) => http.post(`/e/${task.slug}/tasks/${index}/done`),
          { concurrency: 'unbounded' },
        )
        const detail = yield* client.entries.get({ params: { ref: entryRef(task.slug) } })

        expect(responses.map((response) => response.status < BAD_REQUEST)).toEqual([
          true,
          true,
          true,
          true,
        ])
        expect(detail.entry.body).toBe('- [x] one\n- [x] two\n- [x] three\n- [x] four')
      }),
    ))
})

describe('two meeting starts on one event at once', () => {
  test('make one note', () =>
    run(
      Effect.gen(function* () {
        const { client } = yield* session
        const notes = yield* Effect.forEach([0, 1], () => client.meetings.start(), {
          concurrency: 'unbounded',
        })

        expect(new Set(notes.map((note) => note.id)).size).toBe(1)
      }),
    ))
})

describe('a failed seal over the pages', () => {
  const postStatus = (path: string) =>
    Effect.gen(function* () {
      const { http } = yield* session
      const response = yield* refused(http.post(path))

      return { status: response.status, body: yield* response.text }
    })

  test('a new note is a 500 saying nothing was saved', () =>
    run(
      Effect.gen(function* () {
        const answer = yield* postStatus('/notes')

        expect(answer.status).toBe(SERVER_ERROR)
        expect(answer.body).toContain('nothing was saved')
      }),
    ))

  test('claiming a missing slug is a 500, not a bad request', () =>
    run(
      Effect.gen(function* () {
        const answer = yield* postStatus(`/e/${Bun.randomUUIDv7()}/create`)

        expect(answer.status).toBe(SERVER_ERROR)
      }),
    ))

  test('ticking a task is a 500, not a bad request', () =>
    run(
      Effect.gen(function* () {
        const { client } = yield* session
        const task = yield* client.entries.create({
          payload: { type: 'task', body: '- [ ] one' },
        })
        const answer = yield* postStatus(`/e/${task.slug}/tasks/0/done`)

        expect(answer.status).toBe(SERVER_ERROR)
      }),
    ))

  test('the Google callback is a 500, not a bad request', () =>
    run(
      Effect.gen(function* () {
        const { http } = yield* session
        const response = yield* http.execute(
          HttpClientRequest.get('/oauth/google/callback?code=c&state=s').pipe(
            HttpClientRequest.setHeader('cookie', 'oauth_state=s'),
          ),
        )

        expect(response.status).toBe(SERVER_ERROR)
      }),
    ))
})
