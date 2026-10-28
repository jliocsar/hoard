import * as Config from 'effect/Config'
import * as Data from 'effect/Data'
import * as Effect from 'effect/Effect'
import * as FileSystem from 'effect/FileSystem'
import * as Option from 'effect/Option'
import * as Path from 'effect/Path'
import * as Schema from 'effect/Schema'
import * as Stream from 'effect/Stream'
import * as ChildProcess from 'effect/unstable/process/ChildProcess'
import * as ChildProcessSpawner from 'effect/unstable/process/ChildProcessSpawner'

import { EntryId } from '@hoard/web/domain'
import type { EntrySlug } from '@hoard/web/domain'

export interface PulledEntry {
  readonly id: EntryId
  readonly slug: EntrySlug
  readonly version: number
  readonly body: string
}

export type PutResult = Data.TaggedEnum<{
  Saved: { readonly version: number }
  Stale: { readonly version: number; readonly body: string }
}>

export type PutBody<PutError, PutRequirements> = (
  id: EntryId,
  body: string,
  version: number,
) => Effect.Effect<PutResult, PutError, PutRequirements>

export interface PushResult {
  readonly path: string
  readonly pushed: boolean
  readonly merged: boolean
}

export interface MergeResult {
  readonly clean: boolean
  readonly text: string
}

const MAX_PUSH_ATTEMPTS = 3
const PRIVATE_DIR_MODE = 0o700
const PRIVATE_FILE_MODE = 0o600
const GROUP_WRITABLE = 0o020
const WORLD_WRITABLE = 0o002

export const defaultDir = Effect.gen(function* () {
  const path = yield* Path.Path
  const home = yield* Config.string('HOME')
  const cache = yield* Config.string('XDG_CACHE_HOME').pipe(
    Config.withDefault(path.join(home, '.cache')),
  )

  return path.join(cache, 'hoard')
}).pipe(Effect.orDie)

export const PutResult = Data.taggedEnum<PutResult>()

export const Sidecar = Schema.Struct({
  id: EntryId,
  version: Schema.Int,
  base: Schema.String,
})

export type Sidecar = typeof Sidecar.Type

const SidecarJson = Schema.fromJsonString(Sidecar)

export class UnpushedChanges extends Schema.TaggedError<UnpushedChanges>()('UnpushedChanges', {
  path: Schema.String,
  message: Schema.String,
}) {}

export class ConflictMarkers extends Schema.TaggedError<ConflictMarkers>()('ConflictMarkers', {
  path: Schema.String,
  message: Schema.String,
}) {}

export class UnsafeDir extends Schema.TaggedError<UnsafeDir>()('UnsafeDir', {
  path: Schema.String,
  message: Schema.String,
}) {}

export class NotPulled extends Schema.TaggedError<NotPulled>()('NotPulled', {
  path: Schema.String,
  message: Schema.String,
}) {}

export const entryPath = (dir: string, slug: string) =>
  Effect.map(Path.Path, (path) => path.join(dir, `${slug}.md`))

const sidecarPath = (file: string) =>
  Effect.map(Path.Path, (path) =>
    path.join(path.dirname(file), `.${path.basename(file, '.md')}.json`),
  )

const readText = Effect.fn('workspace.readText')(function* (path: string) {
  const fs = yield* FileSystem.FileSystem

  if (yield* Effect.orDie(fs.exists(path))) {
    return Option.some(yield* Effect.orDie(fs.readFileString(path)))
  }

  return Option.none<string>()
})

const ownedByOtherUser = (info: FileSystem.File.Info) => {
  const uid = process.getuid?.()

  return uid !== undefined && Option.isSome(info.uid) && info.uid.value !== uid
}

const writableByOthers = (info: FileSystem.File.Info) => {
  const gid = process.getgid?.()
  const foreignGroup = !(Option.isSome(info.gid) && info.gid.value === gid)

  return (info.mode & WORLD_WRITABLE) !== 0 || ((info.mode & GROUP_WRITABLE) !== 0 && foreignGroup)
}

const unsafeDirReason = (isLink: boolean, info: FileSystem.File.Info) => {
  if (isLink || info.type !== 'Directory') {
    return Option.some('is a symlink or not a directory')
  }

  if (ownedByOtherUser(info)) {
    return Option.some('belongs to another user')
  }

  return writableByOthers(info) ? Option.some('is writable by other users') : Option.none()
}

const checkDir = Effect.fn('workspace.checkDir')(function* (dir: string) {
  const fs = yield* FileSystem.FileSystem
  const isLink = yield* Effect.match(fs.readLink(dir), {
    onFailure: () => false,
    onSuccess: () => true,
  })
  const info = yield* Effect.orDie(fs.stat(dir))

  yield* Option.match(unsafeDirReason(isLink, info), {
    onNone: () => Effect.void,
    onSome: (reason) => Effect.fail(new UnsafeDir({ path: dir, message: `${dir} ${reason}` })),
  })
})

const preparePullDir = Effect.fn('workspace.preparePullDir')(function* (dir: string) {
  const fs = yield* FileSystem.FileSystem

  yield* Effect.orDie(fs.makeDirectory(dir, { recursive: true, mode: PRIVATE_DIR_MODE }))
  yield* checkDir(dir)
})

const writeText = Effect.fn('workspace.writeText')(function* (file: string, text: string) {
  const fs = yield* FileSystem.FileSystem
  const path = yield* Path.Path
  const dir = path.dirname(file)
  const temp = path.join(dir, `.${path.basename(file)}.${Bun.randomUUIDv7()}.tmp`)

  yield* Effect.orDie(fs.makeDirectory(dir, { recursive: true, mode: PRIVATE_DIR_MODE }))
  yield* Effect.orDie(fs.writeFileString(temp, text, { flag: 'wx', mode: PRIVATE_FILE_MODE }))
  yield* Effect.orDie(fs.rename(temp, file))
})

const readSidecar = (file: string) =>
  Effect.flatMap(Effect.flatMap(sidecarPath(file), readText), (text) =>
    Option.match(text, {
      onNone: () => Effect.succeed(Option.none<Sidecar>()),
      onSome: (json) =>
        Effect.map(Effect.orDie(Schema.decodeEffect(SidecarJson)(json)), Option.some),
    }),
  )

const writeSidecar = Effect.fn('workspace.writeSidecar')(function* (
  file: string,
  sidecar: Sidecar,
) {
  const json = yield* Effect.orDie(Schema.encodeEffect(SidecarJson)(sidecar))

  yield* writeText(yield* sidecarPath(file), json)
})

export const pull = Effect.fn('workspace.pull')(function* (
  dir: string,
  entry: PulledEntry,
  force: boolean,
) {
  yield* preparePullDir(dir)

  const file = yield* entryPath(dir, entry.slug)

  if (!force) {
    const local = yield* readText(file)
    const sidecar = yield* readSidecar(file)
    const dirty =
      Option.isSome(local) && (Option.isNone(sidecar) || sidecar.value.base !== local.value)

    if (dirty) {
      return yield* new UnpushedChanges({
        path: file,
        message: 'local edits not pushed; push them first or pull with --force',
      })
    }
  }

  yield* writeText(file, entry.body)
  yield* writeSidecar(file, { id: entry.id, version: entry.version, base: entry.body })

  return file
})

export const merge = Effect.fn('workspace.merge')(function* (
  local: string,
  base: string,
  remote: string,
) {
  const fs = yield* FileSystem.FileSystem
  const path = yield* Path.Path
  const spawner = yield* ChildProcessSpawner.ChildProcessSpawner
  const scratch = yield* Effect.orDie(fs.makeTempDirectoryScoped({ prefix: 'hoard-merge-' }))
  const files = {
    local: path.join(scratch, 'local'),
    base: path.join(scratch, 'base'),
    remote: path.join(scratch, 'remote'),
  }

  yield* writeText(files.local, local)
  yield* writeText(files.base, base)
  yield* writeText(files.remote, remote)

  const child = yield* Effect.orDie(
    spawner.spawn(
      ChildProcess.make('git', [
        'merge-file',
        '-p',
        '-L',
        'local',
        '-L',
        'base',
        '-L',
        'remote',
        files.local,
        files.base,
        files.remote,
      ]),
    ),
  )
  const [text, stderr, code] = yield* Effect.orDie(
    Effect.all(
      [
        Stream.mkString(Stream.decodeText(child.stdout)),
        Stream.mkString(Stream.decodeText(child.stderr)),
        child.exitCode,
      ],
      { concurrency: 'unbounded' },
    ),
  )

  if (code === 0) {
    return { clean: true, text } satisfies MergeResult
  }

  if (code > 0 && code < 128) {
    return { clean: false, text } satisfies MergeResult
  }

  return yield* Effect.die(`git merge-file failed (${code}): ${stderr}`)
}, Effect.scoped)

export const push = Effect.fn('workspace.push')(function* <PutError, PutRequirements>(
  file: string,
  put: PutBody<PutError, PutRequirements>,
) {
  const local = yield* readText(file)
  const sidecar = yield* readSidecar(file)

  if (Option.isNone(local) || Option.isNone(sidecar)) {
    return yield* new NotPulled({ path: file, message: 'no pulled copy here; pull it first' })
  }

  yield* checkDir(yield* Effect.map(Path.Path, (path) => path.dirname(file)))

  const { id } = sidecar.value
  let body = local.value
  let base = sidecar.value.base
  let version = sidecar.value.version

  if (body === base) {
    return { path: file, pushed: false, merged: false } satisfies PushResult
  }

  for (let attempt = 0; attempt < MAX_PUSH_ATTEMPTS; attempt++) {
    const result = yield* put(id, body, version)

    if (PutResult.$is('Saved')(result)) {
      const merged = body !== local.value

      if (merged) {
        yield* writeText(file, body)
      }

      yield* writeSidecar(file, { id, version: result.version, base: body })

      return { path: file, pushed: true, merged } satisfies PushResult
    }

    const merged = yield* merge(body, base, result.body)

    if (!merged.clean) {
      yield* writeText(file, merged.text)
      yield* writeSidecar(file, { id, version: result.version, base: result.body })

      return yield* new ConflictMarkers({
        path: file,
        message: 'overlapping edits; resolve the conflict markers in the file, then push again',
      })
    }

    body = merged.text
    base = result.body
    version = result.version
  }

  return yield* Effect.die(`entry kept changing during push: ${file}`)
})
