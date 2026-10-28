# hoard

A single-user, self-hosted place for notes, meeting notes, task lists and files.
It runs as one Bun process with one SQLite file and one S3 bucket, and it has a CLI
so coding agents can read and write it too.

## What it does

- **Notes.** Markdown in a CodeMirror editor with vim keys. Click **New** and you're
  typing: the server picks the title, and edits save on a ~2s idle.
- **Meeting notes.** It reads your Google Calendar (`calendar.readonly` only). A new
  meeting note picks up whatever meeting is on right now, with its title and attendees.
- **Tasks.** A page of checkboxes, stored as `- [ ]` lines.
- **Artifacts.** Files go straight from the browser to the bucket through presigned URLs
  and come back through short-lived signed URLs. You can share one with a secret,
  revocable `/s/:token` link that can expire.
- **Links and tags.** `[text](@slug)` links any entry to any other. Tags are flat labels
  for filtering.
- **Archive, not delete.** Only archived entries can be deleted, and only from the web UI.
- Installable as a PWA. Hourly database backups go to the bucket.

## How it works

```
browser (htmx + CodeMirror) ─┐
                             ├─> Bun + Effect server ──> SQLite (WAL)
hoard CLI / agents ──────────┘           │
                                         └──> S3 bucket (artifacts/, backups/)
                                         └──> Google Calendar API
```

- **One table.** `entries` holds every type. A section is `WHERE type = ?`. Writes from
  every client go through one `put` with an `expectedVersion`. A stale write fails with
  `VersionConflict`, and the CLI resolves that with a three-way merge.
- **Server-rendered.** Pages are JSX rendered on the server (`packages/jsx`) and
  enhanced with htmx. The API is an Effect `HttpApi` (`apps/web/src/api.ts`) that the
  server and the CLI share, so they can't drift.
- **Encryption at rest.** Entry bodies and Google refresh tokens are encrypted with
  `ENCRYPTION_KEY` before they reach SQLite. Tags and titles are plaintext so they can
  be indexed.
- **Auth.** One password, checked against an argon2id hash, gets a one-year signed
  session token. It's a cookie in the browser and a bearer token in the CLI. Wrong
  passwords take 2 seconds to answer. Three failures from one IP lock that IP out for
  an hour, even with the right password.
- **Artifacts are never served from the app's origin.** That way an uploaded `.html`
  can't run next to your session cookie.

[SPEC.md](SPEC.md) has the full behaviour and the reasons behind it.
[DESIGN.md](DESIGN.md) is the visual spec.

## Layout

```
apps/web        server, pages, API, services (Auth, Entries, Calendar, ObjectStore, …)
apps/cli        the `hoard` CLI
packages/jsx    tiny server-side JSX runtime
skills/hoard    agent skill that teaches the CLI
deploy/         systemd unit
scripts/        deploy script
```

## Running it

You need [Bun](https://bun.sh) 1.4+.

```sh
bun install
cp apps/web/.env.example apps/web/.env   # then fill it in, see below
bun run dev                              # http://localhost:3123
```

| Variable                                           | What it is                                                                                          |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `PASSWORD_HASH`                                    | `bun -e 'console.log(await Bun.password.hash("your password"))'`. Write every `$` as `\$` in `.env` |
| `SESSION_SECRET`                                   | Any long random string. Rotating it logs every browser and CLI out                                  |
| `ENCRYPTION_KEY`                                   | 32 random bytes, base64: `openssl rand -base64 32`                                                  |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`        | OAuth client, redirect URI `<origin>/oauth/google/callback`                                         |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`      | Bucket credentials (Tigris by default)                                                              |
| `BUCKET_NAME`, `AWS_ENDPOINT_URL_S3`, `AWS_REGION` | Bucket name and endpoint                                                                            |

Optional: `PORT` (default `3123`), `DATABASE_PATH` (default `app.db`) and
`BACKUP_ENABLED`.

Checks:

```sh
bun run typecheck && bun run lint && bun run fmt:check
cd apps/web && bun test
```

## CLI

```sh
cd apps/cli && bun run build        # -> apps/cli/dist/hoard
hoard login --url https://your-host
hoard list --type note
hoard pull <slug>                   # edit /tmp/hoard/<slug>.md, then:
hoard push <slug>
```

Every command prints JSON. [skills/hoard/SKILL.md](skills/hoard/SKILL.md) has the
full command list, the exit codes and the pull → edit → push loop.

## Deploying

`bun run deploy` runs [scripts/deploy.sh](scripts/deploy.sh). It targets an
[exe.dev](https://exe.dev) VM: it installs Bun and creates a `hoard` user if they're
missing, rsyncs the source, copies `apps/web/.env` to `/etc/hoard/env`, builds, and
restarts [deploy/hoard.service](deploy/hoard.service). Set `HOARD_HOST` to point it
at your own VM. Any box that can run Bun behind an HTTPS proxy works too. The login
rate limit trusts the last `X-Forwarded-For` entry, so the proxy has to append it.
