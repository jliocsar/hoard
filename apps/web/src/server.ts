import { BunHttpServer, BunRuntime } from '@effect/platform-bun'
import * as Config from 'effect/Config'
import * as Layer from 'effect/Layer'
import * as Aead from 'effect/crypto/Aead'
import * as SecureRandom from 'effect/crypto/SecureRandom'
import * as FetchHttpClient from 'effect/http/FetchHttpClient'
import * as HttpRouter from 'effect/http/HttpRouter'

import { Router } from './router.ts'
import { Auth } from './services/Auth.ts'
import { BackupLayer } from './services/Backup.ts'
import { Calendar } from './services/Calendar.ts'
import { Cipher } from './services/Cipher.ts'
import { DatabaseLayer } from './services/Database.ts'
import { Entries } from './services/Entries.ts'
import { Google } from './services/Google.ts'
import { Markdown } from './services/Markdown.ts'
import { ObjectStore } from './services/ObjectStore.ts'
import { ShareLinks } from './services/ShareLinks.ts'

const EntriesLayer = Entries.layer.pipe(Layer.provideMerge(ObjectStore.layer))

const GoogleLayer = Google.layer.pipe(Layer.provide(FetchHttpClient.layer))

const CipherLayer = Cipher.layer.pipe(
  Layer.provide(Aead.layerWebCrypto.pipe(Layer.provideMerge(SecureRandom.layerWebCrypto))),
)

const Services = Layer.mergeAll(
  Auth.layer,
  SecureRandom.layerWebCrypto,
  Layer.mergeAll(
    Markdown.layer.pipe(Layer.provideMerge(EntriesLayer)),
    ShareLinks.layer,
    Calendar.layer.pipe(Layer.provideMerge(GoogleLayer)),
    BackupLayer.pipe(Layer.provide(ObjectStore.layer)),
  ).pipe(Layer.provide(Layer.mergeAll(DatabaseLayer, CipherLayer))),
  BunHttpServer.layerConfig({ port: Config.Port('PORT').pipe(Config.withDefault(3123)) }),
)

const MainLayer = HttpRouter.serve(Router).pipe(Layer.provide(Services))

BunRuntime.runMain(Layer.launch(MainLayer))
