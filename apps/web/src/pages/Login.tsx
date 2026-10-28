import { Layout } from '../components/Layout.tsx'

export type LoginFailure = 'wrong-password' | 'too-many-attempts'

const FAILURE_MESSAGE = {
  'wrong-password': 'Wrong password',
  'too-many-attempts': 'Too many attempts. Try again in an hour',
} satisfies Record<LoginFailure, string>

export const LoginPage = (props: {
  readonly next: string
  readonly failure: LoginFailure | null
}) => (
  <Layout title="Sign in" guest>
    <main class="flex min-h-dvh items-center justify-center px-4">
      <form
        method="post"
        action="/login"
        hx-boost="false"
        class="flex w-full max-w-[280px] flex-col gap-3"
      >
        <h1 class="font-serif text-[34px] leading-[1.15] font-normal tracking-[-0.01em]">
          Sign in
        </h1>
        <input type="hidden" name="next" value={props.next} />
        <input
          class="input w-full"
          type="password"
          name="password"
          placeholder="Password"
          autocomplete="current-password"
          aria-invalid={props.failure !== null}
          autofocus
          required
        />
        {props.failure === null ? null : (
          <p class="text-xs text-muted-foreground">{FAILURE_MESSAGE[props.failure]}</p>
        )}
        <button type="submit" class="btn w-full">
          Sign in
        </button>
      </form>
    </main>
  </Layout>
)
