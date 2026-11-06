import { afterAll, afterEach, describe, expect, test } from 'bun:test'
import { createDecipheriv } from 'node:crypto'
import * as ConfigProvider from 'effect/ConfigProvider'
import * as DateTime from 'effect/DateTime'
import * as Deferred from 'effect/Deferred'
import * as Effect from 'effect/Effect'
import * as Exit from 'effect/Exit'
import * as Fiber from 'effect/Fiber'
import * as Layer from 'effect/Layer'
import * as ManagedRuntime from 'effect/ManagedRuntime'
import * as Option from 'effect/Option'
import * as Result from 'effect/Result'
import * as Schema from 'effect/Schema'
import * as Aead from 'effect/crypto/Aead'
import * as CryptoError from 'effect/crypto/CryptoError'
import * as SecureRandom from 'effect/crypto/SecureRandom'
import * as SqlClient from 'effect/sql/SqlClient'
import * as SqlSchema from 'effect/sql/SqlSchema'

import { entryId, entryRef, googleAccountId, SealFailed, VersionConflict } from '../domain.ts'
import { Calendar } from './Calendar.ts'
import { Cipher, InvalidEncryptionKey, UnsealFailed } from './Cipher.ts'
import { DatabaseLayer } from './Database.ts'
import { Entries } from './Entries.ts'
import { Google } from './Google.ts'
import { ObjectStore } from './ObjectStore.ts'

interface SealingControl {
  before: Effect.Effect<void, CryptoError.CryptoError>
  calls: number
}

type Stored = Entries | Calendar | Cipher | ObjectStore | SqlClient.SqlClient | Google

const KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
const OTHER_KEY = 'HxwdHhkaGxgVFhcUERITEA0ODwwJCgsIBQYHBAECAwA='
const SEALED_PREFIX = 'enc:v1:'
const IV_BYTES = 12
const TAG_BYTES = 16
const SEALS_FOR_DISTINCT_IVS = 1000

const FIXTURES = [
  {
    label: 'empty',
    plain: '',
    opened: '',
    sealed: 'enc:v1:w7xKtgb1nGGGiD3e+1elFvdrwR4Cw47JXGNv2w==',
  },
  {
    label: 'ascii',
    plain: 'plain ascii note',
    opened: 'plain ascii note',
    sealed: 'enc:v1:mJtdcTt6lwI24Awjw4jblXZh7h0tY2lUiPuWFjgDo0XdCKAG1WCi4mo4Huc=',
  },
  {
    label: 'accented',
    plain: 'Acentuação: São Paulo, coração, maçã',
    opened: 'Acentuação: São Paulo, coração, maçã',
    sealed:
      'enc:v1:A8W2k5C7NFmNGsXDFqotL6K4HTTl1euekt81MptB94ErkksfDGp5626qfLbY2NHZC1hMsej8SWEWzfanSsInz57nrnSsz/Q=',
  },
  {
    label: 'cjk and emoji',
    plain: '日本語のメモ 🧠🔐',
    opened: '日本語のメモ 🧠🔐',
    sealed: 'enc:v1:bDM8bvvh8rH7qVUhVZ36RKNu+tZcV+0/+/wqSEdQNmowG/hBWFEMV3biKg4MEa5892yjuJEytQ==',
  },
  {
    label: 'leading byte order mark',
    plain: '﻿starts with a BOM',
    opened: '﻿starts with a BOM',
    sealed: 'enc:v1:TO8AcdQvU0X8hbUmUl3RrsmYqhVvomqImoTXoU0/LE5bcSU30ORbJ5Nt1Hghdtb0',
  },
  {
    label: 'control characters',
    plain: 'line one\n\n- [ ] task\r\n\ttabbed\u0000nul ',
    opened: 'line one\n\n- [ ] task\r\n\ttabbed\u0000nul ',
    sealed:
      'enc:v1:/vr0pYVPMBgUsgBWmuOZkpKpe+p/H3uimp7KELhCmTTAEaQhLQWcMa+yf3paImB7AwEPHZnTm/4uh4991k8=',
  },
  {
    label: 'looks sealed',
    plain: 'enc:v1:not actually sealed',
    opened: 'enc:v1:not actually sealed',
    sealed: 'enc:v1:idkk3fNRA4QEXAlV+jJprVKSSYqcXBGhNBv+97QHSnHM9u/LO57sYsJvfyInBRb/bi60hxNr',
  },
  {
    label: 'lone surrogate',
    plain: 'broken \ud83d pair',
    opened: 'broken � pair',
    sealed: 'enc:v1:fCBJXIMYjlS0IFTbdCpYc4pZdCG1qyC+KSj3qBYO0BASdEcQ91o4QGkeTg==',
  },
  {
    label: 'past the buffer pool',
    plain: 'long note '.repeat(500),
    opened: 'long note '.repeat(500),
    sealed:
      'enc:v1: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',
  },
]

const unpack = (stored: string) => {
  const packed = Buffer.from(stored.slice(SEALED_PREFIX.length), 'base64')

  return {
    iv: packed.subarray(0, IV_BYTES),
    tag: packed.subarray(IV_BYTES, IV_BYTES + TAG_BYTES),
    ciphertext: packed.subarray(IV_BYTES + TAG_BYTES),
  }
}

const openWithNodeCrypto = (stored: string) => {
  const { iv, tag, ciphertext } = unpack(stored)
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(KEY, 'base64'), iv)

  decipher.setAuthTag(tag)

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
}

const flipByteAt = (stored: string, index: number) => {
  const packed = Buffer.from(stored.slice(SEALED_PREFIX.length), 'base64')

  packed.writeUInt8(packed.readUInt8(index) ^ 0xff, index)

  return `${SEALED_PREFIX}${packed.toString('base64')}`
}

const configFor = (key: string) =>
  ConfigProvider.layer(ConfigProvider.fromUnknown({ ENCRYPTION_KEY: key }))

const RealCrypto = Aead.layerWebCrypto.pipe(Layer.provideMerge(SecureRandom.layerWebCrypto))

const cipherOver = (key: string, crypto: Layer.Layer<Aead.Aead | SecureRandom.SecureRandom>) =>
  Cipher.layer.pipe(Layer.provide(Layer.mergeAll(crypto, configFor(key))))

const runOver = <Success, Failure, Services, LayerFailure>(
  layer: Layer.Layer<Services, LayerFailure>,
  effect: Effect.Effect<Success, Failure, Services>,
) => Effect.runPromise(effect.pipe(Effect.provide(layer)))

const runtime = ManagedRuntime.make(cipherOver(KEY, RealCrypto))

const run = <Success, Failure>(effect: Effect.Effect<Success, Failure, Cipher>) =>
  runtime.runPromise(effect)

const REFUSAL = new CryptoError.CryptoError({
  module: 'Aead',
  method: 'encrypt',
  reason: new CryptoError.Unsupported({ description: 'refused by the test' }),
})

const encryptRefused = Effect.fail(REFUSAL)

const sealing: SealingControl = {
  before: Effect.void,
  calls: 0,
}

const ControlledAead = Layer.effect(Aead.Aead)(
  Effect.gen(function* () {
    const real = yield* Aead.Aead

    return {
      ...real,
      encrypt: (key, plaintext, options) =>
        Effect.suspend(() => {
          sealing.calls += 1

          return Effect.andThen(sealing.before, real.encrypt(key, plaintext, options))
        }),
    } satisfies typeof Aead.Aead.Service
  }),
).pipe(Layer.provide(RealCrypto))

const StoreConfig = ConfigProvider.layer(
  ConfigProvider.fromUnknown({ ENCRYPTION_KEY: KEY, DATABASE_PATH: ':memory:' }),
)

const FakeObjectStore = Layer.mock(ObjectStore)({
  origin: 'https://bucket.test',
  uploadUrl: (key) => `https://bucket.test/${key}?put`,
  downloadUrl: (key) => `https://bucket.test/${key}?get`,
})

const FakeGoogle = Layer.mock(Google)({
  authUrl: () => 'https://google.test/auth',
  exchange: () =>
    Effect.map(DateTime.now, (now) => ({
      token: 'access',
      expiresAt: DateTime.addDuration(now, '1 hour'),
      refreshToken: 'refresh token',
    })),
  primaryEmail: () => Effect.succeed('owner@example.test'),
  selectedCalendars: () => Effect.succeed(['primary']),
})

const Sealing = Cipher.layer.pipe(
  Layer.provide(Layer.mergeAll(ControlledAead, SecureRandom.layerWebCrypto)),
)

const Storage = Layer.mergeAll(DatabaseLayer, Sealing, FakeObjectStore, FakeGoogle)

const StoreServices = Layer.mergeAll(Entries.layer, Calendar.layer).pipe(
  Layer.provideMerge(Storage),
)

const store = ManagedRuntime.make(StoreServices.pipe(Layer.provide(StoreConfig)))

const inStore = <Success, Failure>(effect: Effect.Effect<Success, Failure, Stored>) =>
  store.runPromise(effect)

const newNote = (body: string) =>
  Effect.gen(function* () {
    const entries = yield* Entries

    return yield* entries.create({
      type: 'note',
      title: Option.some(Bun.randomUUIDv7()),
      zone: DateTime.zoneMakeOffset(0),
      body,
    })
  })

const storedEntry = (id: string) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient
    const rows = yield* SqlSchema.findAll({
      Request: Schema.String,
      Result: Schema.Struct({ body: Schema.String, version: Schema.Int }),
      execute: (entry) => sql`SELECT body, version FROM entries WHERE id = ${entry}`,
    })(id)

    return rows.at(0)
  })

const storedToken = (id: string) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient
    const rows = yield* SqlSchema.findAll({
      Request: Schema.String,
      Result: Schema.Struct({ refresh_token: Schema.String }),
      execute: (account) => sql`SELECT refresh_token FROM google_accounts WHERE id = ${account}`,
    })(id)

    return rows.at(0)?.refresh_token
  })

const insertRawEntry = (body: string) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient
    const id = entryId(Bun.randomUUIDv7())
    const now = '2026-01-01T00:00:00.000Z'

    yield* sql`
      INSERT INTO entries ${sql.insert({
        id,
        type: 'note',
        slug: id,
        title: id,
        body,
        created_at: now,
        updated_at: now,
        version: 1,
      })}
    `

    return id
  })

afterEach(() => {
  sealing.before = Effect.void
  sealing.calls = 0
})

afterAll(() => Promise.all([runtime.dispose(), store.dispose()]))

describe('rows sealed by the node:crypto implementation', () => {
  test('hold iv, tag and ciphertext behind the prefix', () => {
    for (const fixture of FIXTURES) {
      expect(fixture.sealed.startsWith(SEALED_PREFIX)).toBe(true)
      expect(openWithNodeCrypto(fixture.sealed)).toBe(fixture.opened)
      expect(unpack(fixture.sealed).ciphertext.length).toBe(Buffer.byteLength(fixture.opened))
    }
  })

  test('open through Cipher.open', () =>
    run(
      Effect.gen(function* () {
        const cipher = yield* Cipher

        for (const fixture of FIXTURES) {
          expect(yield* cipher.open(fixture.sealed)).toBe(fixture.opened)
        }
      }),
    ))

  test('open through the Sealed codec', () =>
    run(
      Effect.gen(function* () {
        const cipher = yield* Cipher

        for (const fixture of FIXTURES) {
          expect(yield* Schema.decodeEffect(cipher.Sealed)(fixture.sealed)).toBe(fixture.opened)
        }
      }),
    ))

  test('read back through Entries, row for row', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries

        for (const fixture of FIXTURES) {
          const id = yield* insertRawEntry(fixture.sealed)
          const read = yield* entries.byRef(entryRef(id))
          const raw = yield* storedEntry(id)

          expect(read.body).toBe(fixture.opened)
          expect(raw?.body).toBe(fixture.sealed)
        }
      }),
    ))
})

describe('rows Cipher seals', () => {
  test('open with node:crypto, the way an older binary reads them', () =>
    run(
      Effect.gen(function* () {
        const cipher = yield* Cipher

        for (const fixture of FIXTURES) {
          const sealed = yield* cipher.seal(fixture.plain)
          const { iv, tag, ciphertext } = unpack(sealed)

          expect(sealed.startsWith(SEALED_PREFIX)).toBe(true)
          expect(iv.length).toBe(IV_BYTES)
          expect(tag.length).toBe(TAG_BYTES)
          expect(ciphertext.length).toBe(Buffer.byteLength(fixture.opened))
          expect(openWithNodeCrypto(sealed)).toBe(fixture.opened)
          expect(yield* cipher.open(sealed)).toBe(fixture.opened)
        }
      }),
    ))

  test('match the old implementation byte for byte under the same iv', () =>
    Promise.all(
      FIXTURES.map((fixture) => {
        const iv = new Uint8Array(unpack(fixture.sealed).iv)
        const FixedRandom = Layer.mock(SecureRandom.SecureRandom)({
          randomBytes: () => Effect.succeed(iv),
        })
        const crypto = Aead.layerWebCrypto.pipe(Layer.provideMerge(FixedRandom))

        return runOver(
          cipherOver(KEY, crypto),
          Effect.gen(function* () {
            const cipher = yield* Cipher

            expect(yield* cipher.seal(fixture.plain)).toBe(fixture.sealed)
          }),
        )
      }),
    ))

  test('never repeat an iv', () =>
    run(
      Effect.gen(function* () {
        const cipher = yield* Cipher
        const seals = yield* Effect.forEach(Array.from({ length: SEALS_FOR_DISTINCT_IVS }), () =>
          cipher.seal('the same value'),
        )

        expect(new Set(seals.map((sealed) => unpack(sealed).iv.toString('hex'))).size).toBe(
          SEALS_FOR_DISTINCT_IVS,
        )
        expect(new Set(seals).size).toBe(SEALS_FOR_DISTINCT_IVS)
      }),
    ))
})

describe('a value that does not open', () => {
  test('tampered iv, tag or ciphertext fails with UnsealFailed', () =>
    run(
      Effect.gen(function* () {
        const cipher = yield* Cipher
        const stored = FIXTURES.find((fixture) => fixture.label === 'ascii')?.sealed ?? ''

        for (const index of [0, IV_BYTES, IV_BYTES + TAG_BYTES]) {
          const error = yield* Effect.flip(cipher.open(flipByteAt(stored, index)))

          expect(error).toBeInstanceOf(UnsealFailed)
          expect(error.message).toContain('ENCRYPTION_KEY')
        }
      }),
    ))

  test('a wrong key fails with UnsealFailed for every fixture', () =>
    runOver(
      cipherOver(OTHER_KEY, RealCrypto),
      Effect.gen(function* () {
        const cipher = yield* Cipher

        for (const fixture of FIXTURES) {
          expect(yield* Effect.flip(cipher.open(fixture.sealed))).toBeInstanceOf(UnsealFailed)
        }
      }),
    ))

  test('a truncated or malformed value fails with UnsealFailed', () =>
    run(
      Effect.gen(function* () {
        const cipher = yield* Cipher
        const stored = FIXTURES.find((fixture) => fixture.label === 'empty')?.sealed ?? ''

        for (const broken of [
          SEALED_PREFIX,
          `${SEALED_PREFIX}not base64 at all!`,
          `${SEALED_PREFIX}AAAA`,
          stored.slice(0, stored.length - 8),
        ]) {
          expect(yield* Effect.flip(cipher.open(broken))).toBeInstanceOf(UnsealFailed)
        }
      }),
    ))

  test('fails the Sealed codec with a schema error naming the cause', () =>
    run(
      Effect.gen(function* () {
        const cipher = yield* Cipher
        const stored = FIXTURES.find((fixture) => fixture.label === 'ascii')?.sealed ?? ''
        const error = yield* Effect.flip(
          Schema.decodeEffect(cipher.Sealed)(flipByteAt(stored, IV_BYTES)),
        )

        expect(error).toBeInstanceOf(Schema.SchemaError)
        expect(error.message).toContain('ENCRYPTION_KEY')
      }),
    ))
})

describe('legacy plaintext', () => {
  const LEGACY_VALUES = ['', 'no prefix here', 'enc:v2:other', ' enc:v1:not at the start']

  test('passes through open and the Sealed codec unchanged', () =>
    run(
      Effect.gen(function* () {
        const cipher = yield* Cipher

        for (const plain of LEGACY_VALUES) {
          expect(cipher.isSealed(plain)).toBe(false)
          expect(yield* cipher.open(plain)).toBe(plain)
          expect(yield* Schema.decodeEffect(cipher.Sealed)(plain)).toBe(plain)
        }
      }),
    ))

  test('never reaches the cipher', () =>
    runOver(
      cipherOver(KEY, Layer.mergeAll(Layer.mock(Aead.Aead)({}), SecureRandom.layerWebCrypto)),
      Effect.gen(function* () {
        const cipher = yield* Cipher

        for (const plain of LEGACY_VALUES) {
          expect(yield* cipher.open(plain)).toBe(plain)
        }
      }),
    ))

  test('a body is sealed on boot, and a sealed one is left byte for byte', () =>
    inStore(
      Effect.gen(function* () {
        const plainId = yield* insertRawEntry('a body from before encryption')
        const emptyId = yield* insertRawEntry('')
        const sealedFixture = FIXTURES.find((fixture) => fixture.label === 'accented')?.sealed ?? ''
        const sealedId = yield* insertRawEntry(sealedFixture)

        yield* Entries.make

        const plainRow = yield* storedEntry(plainId)
        const emptyRow = yield* storedEntry(emptyId)
        const sealedRow = yield* storedEntry(sealedId)

        expect(openWithNodeCrypto(plainRow?.body ?? '')).toBe('a body from before encryption')
        expect(openWithNodeCrypto(emptyRow?.body ?? '')).toBe('')
        expect(sealedRow?.body).toBe(sealedFixture)
      }),
    ))

  test('a refresh token stays as stored, and still reads', () =>
    inStore(
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const calendar = yield* Calendar
        const id = googleAccountId(Bun.randomUUIDv7())

        yield* sql`
          INSERT INTO google_accounts ${sql.insert({
            id,
            email: 'legacy@example.test',
            calendar_ids: '["primary"]',
            refresh_token: 'legacy plaintext token',
            created_at: '2026-01-01T00:00:00.000Z',
          })}
        `

        yield* Entries.make

        const accounts = yield* calendar.accounts

        expect(accounts.find((account) => account.id === id)?.refreshToken).toBe(
          'legacy plaintext token',
        )
        expect(yield* storedToken(id)).toBe('legacy plaintext token')

        yield* calendar.disconnect(id)
      }),
    ))
})

describe('the encryption key', () => {
  test('of the wrong length fails the layer with InvalidEncryptionKey', () =>
    runOver(
      Layer.mergeAll(RealCrypto, configFor('dG9vIHNob3J0')),
      Effect.gen(function* () {
        const error = yield* Effect.flip(Cipher.make)

        expect(error).toBeInstanceOf(InvalidEncryptionKey)
        expect(error.message).toContain('ENCRYPTION_KEY')
      }),
    ))
})

describe('the codecs', () => {
  test('refuse to seal, so a failed seal cannot lose its type', () =>
    run(
      Effect.gen(function* () {
        const cipher = yield* Cipher
        const error = yield* Effect.flip(Schema.encodeEffect(cipher.Sealed)('value'))

        expect(error).toBeInstanceOf(Schema.SchemaError)
        expect(error.message).toContain('Cipher.seal')
      }),
    ))
})

describe('a seal that fails', () => {
  test('is a SealFailed naming no detail', () =>
    runOver(
      cipherOver(
        KEY,
        Layer.mergeAll(
          Layer.mock(Aead.Aead)({ encrypt: () => encryptRefused }),
          SecureRandom.layerWebCrypto,
        ),
      ),
      Effect.gen(function* () {
        const cipher = yield* Cipher
        const error = yield* Effect.flip(cipher.seal('a secret value'))

        expect(error).toBeInstanceOf(SealFailed)
        expect(error.message).toContain('nothing was saved')
        expect(error.message).not.toContain('a secret value')
      }),
    ))

  test('rolls a put back when the cipher dies instead of failing', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries
        const note = yield* newNote('kept')
        const before = yield* storedEntry(note.id)

        sealing.before = Effect.die('a native failure effect/crypto does not classify')

        const exit = yield* Effect.exit(
          entries.put({ id: note.id, body: 'lost', expectedVersion: note.version }),
        )

        expect(Exit.isFailure(exit)).toBe(true)
        expect(yield* storedEntry(note.id)).toEqual(before)
      }),
    ))

  test('rolls a put back', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries
        const note = yield* newNote('kept')
        const before = yield* storedEntry(note.id)

        sealing.before = encryptRefused

        const error = yield* Effect.flip(
          entries.put({ id: note.id, body: 'lost', title: 'lost', expectedVersion: note.version }),
        )

        expect(error).toBeInstanceOf(SealFailed)
        expect(yield* storedEntry(note.id)).toEqual(before)
      }),
    ))

  test('leaves no entry behind on create', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries
        const title = Bun.randomUUIDv7()

        sealing.before = encryptRefused

        const error = yield* Effect.flip(
          entries.create({
            type: 'note',
            title: Option.some(title),
            zone: DateTime.zoneMakeOffset(0),
          }),
        )

        expect(error).toBeInstanceOf(SealFailed)
        expect(yield* entries.takenTitles('note', [title])).toEqual(new Set())
      }),
    ))

  test('rolls back every artifact in the batch', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries
        const titles = [Bun.randomUUIDv7(), Bun.randomUUIDv7()]

        sealing.before = Effect.suspend(() => (sealing.calls === 1 ? Effect.void : encryptRefused))

        const error = yield* Effect.flip(
          entries.createArtifacts(
            titles.map((title) => ({
              title,
              objectKey: `artifacts/${title}`,
              mime: 'text/plain',
              bytes: 1,
            })),
          ),
        )

        expect(error).toBeInstanceOf(SealFailed)
        expect(sealing.calls).toBe(2)
        expect(yield* entries.takenTitles('artifact', titles)).toEqual(new Set())
      }),
    ))

  test('keeps a Google refresh token out of the table', () =>
    inStore(
      Effect.gen(function* () {
        const calendar = yield* Calendar
        const before = yield* calendar.accounts

        sealing.before = encryptRefused

        expect(yield* Effect.flip(calendar.connect('code', 'https://app.test/cb'))).toBeInstanceOf(
          SealFailed,
        )
        expect(yield* calendar.accounts).toEqual(before)
      }),
    ))
})

describe('what the store writes', () => {
  test('create, put and an empty artifact all open with node:crypto', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries
        const note = yield* newNote('first é')
        const created = yield* storedEntry(note.id)

        expect(openWithNodeCrypto(created?.body ?? '')).toBe('first é')

        const next = yield* entries.put({
          id: note.id,
          body: 'second 🧠',
          expectedVersion: note.version,
        })
        const saved = yield* storedEntry(note.id)

        expect(next.body).toBe('second 🧠')
        expect(saved?.version).toBe(note.version + 1)
        expect(openWithNodeCrypto(saved?.body ?? '')).toBe('second 🧠')

        const { created: artifacts } = yield* entries.createArtifacts([
          {
            title: Bun.randomUUIDv7(),
            objectKey: `artifacts/${Bun.randomUUIDv7()}`,
            mime: 'text/plain',
            bytes: 1,
          },
        ])
        const artifact = yield* storedEntry(artifacts.at(0)?.id ?? '')

        expect(openWithNodeCrypto(artifact?.body ?? 'missing')).toBe('')
      }),
    ))

  test('a title-only put seals the same body under a fresh iv', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries
        const note = yield* newNote('same body')
        const before = yield* storedEntry(note.id)

        yield* entries.put({ id: note.id, title: 'renamed', expectedVersion: note.version })

        const after = yield* storedEntry(note.id)

        expect(after?.body).not.toBe(before?.body)
        expect(openWithNodeCrypto(after?.body ?? '')).toBe('same body')
      }),
    ))

  test('setMeeting neither seals nor touches the stored body', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries
        const note = yield* newNote('meeting body')
        const before = yield* storedEntry(note.id)
        const now = yield* DateTime.now

        sealing.before = encryptRefused
        sealing.calls = 0

        yield* entries.setMeeting({
          id: note.id,
          title: 'standup',
          meeting: { accountId: null, start: now, attendees: [] },
        })

        const after = yield* storedEntry(note.id)

        expect(sealing.calls).toBe(0)
        expect(after?.body).toBe(before?.body)
        expect(after?.version).toBe(note.version + 1)
      }),
    ))

  test('two connects for one email at once make one row', () =>
    inStore(
      Effect.gen(function* () {
        const calendar = yield* Calendar
        const accounts = yield* Effect.forEach(
          [0, 1],
          () => calendar.connect('code', 'https://app.test/cb'),
          { concurrency: 'unbounded' },
        )

        expect((yield* calendar.accounts).length).toBe(1)
        expect(accounts.at(0)?.id).toBe(accounts.at(1)?.id ?? googleAccountId(''))

        yield* calendar.disconnect(accounts.at(0)?.id ?? googleAccountId(''))
      }),
    ))

  test('a connected account stores its token sealed', () =>
    inStore(
      Effect.gen(function* () {
        const calendar = yield* Calendar
        const account = yield* calendar.connect('code', 'https://app.test/cb')

        expect(openWithNodeCrypto((yield* storedToken(account.id)) ?? '')).toBe('refresh token')
        expect((yield* calendar.accounts).at(-1)?.refreshToken).toBe('refresh token')

        yield* calendar.disconnect(account.id)
      }),
    ))
})

describe('a transaction waiting on the cipher', () => {
  test('keeps another request out of it', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries
        const note = yield* newNote('kept')
        const entered = yield* Deferred.make<void>()
        const release = yield* Deferred.make<void, CryptoError.CryptoError>()
        const finished = { other: false }

        sealing.calls = 0
        sealing.before = Effect.suspend(() =>
          sealing.calls === 1
            ? Effect.andThen(Deferred.succeed(entered, undefined), Deferred.await(release))
            : Effect.void,
        )

        const held = yield* Effect.forkChild(
          Effect.flip(entries.put({ id: note.id, body: 'lost', expectedVersion: note.version })),
        )

        yield* Deferred.await(entered)

        const other = yield* Effect.forkChild(
          newNote('survives').pipe(
            Effect.tap(() => Effect.sync(() => void (finished.other = true))),
          ),
        )

        yield* Effect.sleep('20 millis')

        expect(finished.other).toBe(false)

        yield* Deferred.fail(release, REFUSAL)

        expect(yield* Fiber.join(held)).toBeInstanceOf(SealFailed)

        const survivor = yield* Fiber.join(other)

        expect(finished.other).toBe(true)
        expect((yield* storedEntry(note.id))?.version).toBe(note.version)
        expect(openWithNodeCrypto((yield* storedEntry(survivor.id))?.body ?? '')).toBe('survives')
      }),
    ))

  test('rolls back when interrupted, and frees the connection', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries
        const note = yield* newNote('kept')
        const entered = yield* Deferred.make<void>()

        sealing.before = Effect.andThen(Deferred.succeed(entered, undefined), Effect.never)

        const held = yield* Effect.forkChild(
          entries.put({ id: note.id, body: 'lost', expectedVersion: note.version }),
        )

        yield* Deferred.await(entered)
        yield* Fiber.interrupt(held)

        sealing.before = Effect.void

        expect((yield* storedEntry(note.id))?.version).toBe(note.version)

        const next = yield* entries.put({
          id: note.id,
          body: 'saved',
          expectedVersion: note.version,
        })

        expect(next.version).toBe(note.version + 1)
      }),
    ))

  test('two puts at one version: one wins, one conflicts', () =>
    inStore(
      Effect.gen(function* () {
        const entries = yield* Entries
        const note = yield* newNote('start')
        const results = yield* Effect.forEach(
          ['left', 'right'],
          (body) =>
            Effect.result(entries.put({ id: note.id, body, expectedVersion: note.version })),
          { concurrency: 'unbounded' },
        )
        const won = results.filter(Result.isSuccess)
        const lost = results.filter(Result.isFailure)

        expect(won.length).toBe(1)
        expect(lost.length).toBe(1)
        expect(lost.at(0)?.failure).toBeInstanceOf(VersionConflict)
        expect((yield* storedEntry(note.id))?.version).toBe(note.version + 1)
        expect((yield* entries.byRef(entryRef(note.id))).body).toBe(won.at(0)?.success.body ?? '')
      }),
    ))
})
