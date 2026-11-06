import * as Config from 'effect/Config'
import * as Context from 'effect/Context'
import * as Effect from 'effect/Effect'
import * as Layer from 'effect/Layer'
import * as Redacted from 'effect/Redacted'
import * as Schema from 'effect/Schema'
import * as SchemaGetter from 'effect/SchemaGetter'
import * as SchemaIssue from 'effect/SchemaIssue'
import * as Aead from 'effect/crypto/Aead'
import * as SecureRandom from 'effect/crypto/SecureRandom'

import type { Entry as DomainEntry } from '../domain.ts'
import { entryFields, ENTRY_KEYS, SealFailed } from '../domain.ts'

export interface CipherShape {
  readonly seal: (plain: string) => Effect.Effect<string, SealFailed>
  readonly open: (stored: string) => Effect.Effect<string, UnsealFailed>
  readonly isSealed: (stored: string) => boolean
  readonly Sealed: Schema.Codec<string, string>
  readonly Entry: Schema.Codec<DomainEntry, typeof DomainEntry.Encoded>
}

const IV_BYTES = 12
const TAG_BYTES = 16
const SEALED_PREFIX = 'enc:v1:'

export class InvalidEncryptionKey extends Schema.TaggedError<InvalidEncryptionKey>()(
  'InvalidEncryptionKey',
  {},
) {
  override get message() {
    return `ENCRYPTION_KEY must be ${Aead.aes256Gcm.keyLength} bytes, base64 encoded`
  }
}

export class UnsealFailed extends Schema.TaggedError<UnsealFailed>()('UnsealFailed', {
  cause: Schema.Unknown,
}) {
  override get message() {
    return 'A sealed value did not open: it was altered, or ENCRYPTION_KEY is not the key that sealed it.'
  }
}

const packRow = (iv: Uint8Array, ciphertextThenTag: Uint8Array) => {
  const tagStart = ciphertextThenTag.length - TAG_BYTES
  const packed = Buffer.concat([
    iv,
    ciphertextThenTag.subarray(tagStart),
    ciphertextThenTag.subarray(0, tagStart),
  ])

  return `${SEALED_PREFIX}${packed.toString('base64')}`
}

const unpackRow = (stored: string) => {
  const packed = Buffer.from(stored.slice(SEALED_PREFIX.length), 'base64')

  return {
    iv: packed.subarray(0, IV_BYTES),
    ciphertextThenTag: Buffer.concat([
      packed.subarray(IV_BYTES + TAG_BYTES),
      packed.subarray(IV_BYTES, IV_BYTES + TAG_BYTES),
    ]),
  }
}

const isSealed = (stored: string) => stored.startsWith(SEALED_PREFIX)

export class Cipher extends Context.Service<Cipher, CipherShape>()('app/Cipher', {
  make: Effect.gen(function* () {
    const aead = yield* Aead.Aead
    const random = yield* SecureRandom.SecureRandom
    const keyBytes = yield* Config.Redacted('ENCRYPTION_KEY').pipe(
      Config.map((value) => Buffer.from(Redacted.value(value), 'base64')),
    )
    const key = yield* Aead.key(Aead.aes256Gcm, keyBytes).pipe(
      Effect.mapError(() => new InvalidEncryptionKey()),
    )

    const seal = Effect.fn('Cipher.seal')(
      function* (plain: string) {
        const iv = yield* random.randomBytes(IV_BYTES)
        const ciphertextThenTag = yield* aead.encrypt(key, new TextEncoder().encode(plain), {
          nonce: iv,
        })

        return packRow(iv, ciphertextThenTag)
      },
      Effect.tapError((error) => Effect.logError('seal failed', error.message)),
      Effect.mapError(() => new SealFailed()),
    )

    const unseal = Effect.fnUntraced(
      function* (stored: string) {
        const { iv, ciphertextThenTag } = unpackRow(stored)
        const plain = yield* aead.decrypt(key, ciphertextThenTag, { nonce: iv })

        return Buffer.from(plain).toString('utf8')
      },
      Effect.mapError((cause) => new UnsealFailed({ cause })),
    )

    const open = (stored: string) => (isSealed(stored) ? unseal(stored) : Effect.succeed(stored))

    const SealedString = Schema.String.pipe(
      Schema.decode({
        decode: SchemaGetter.transformEffect((stored: string, options) =>
          open(stored).pipe(
            Effect.mapError(
              (error) => new SchemaIssue.InvalidValue({ message: error.message }, stored, options),
            ),
          ),
        ),
        encode: SchemaGetter.forbidden(() => 'A codec cannot seal: call Cipher.seal.'),
      }),
    )

    const Entry = Schema.Struct({ ...entryFields, body: SealedString }).pipe(
      Schema.encodeKeys(ENTRY_KEYS),
    )

    return {
      seal,
      open,
      isSealed,
      Sealed: SealedString,
      Entry,
    } satisfies CipherShape
  }),
}) {
  static readonly layer = Layer.effect(this)(this.make)
}
