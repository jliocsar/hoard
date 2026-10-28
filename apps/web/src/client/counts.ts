import * as Effect from 'effect/Effect'
import * as Ref from 'effect/Ref'
import * as Stream from 'effect/Stream'
import NumberFlow, { define } from 'number-flow'

type Counts = ReadonlyMap<string, number>

interface SwapDetail {
  readonly requestConfig?: { readonly triggeringEvent?: Event | null }
  readonly pathInfo?: { readonly requestPath?: string }
}

const NONE: Counts = new Map()
const EASE_OUT = 'cubic-bezier(0.23, 1, 0.32, 1)'

define('number-flow', NumberFlow)

const countElements = () => Array.from(document.querySelectorAll<HTMLElement>('[data-count]'))

const readCounts = (): Counts =>
  new Map(
    countElements().map((element) => [element.dataset['count'] ?? '', Number(element.textContent)]),
  )

const pointerOnSamePage = (detail: SwapDetail) => {
  const trigger = detail.requestConfig?.triggeringEvent
  const path = detail.pathInfo?.requestPath

  return (
    trigger instanceof MouseEvent &&
    trigger.detail > 0 &&
    path !== undefined &&
    new URL(path, location.href).pathname === location.pathname
  )
}

const roll = (element: HTMLElement, from: number, to: number) => {
  const flow = document.createElement('number-flow')
  flow.transformTiming = { duration: 300, easing: EASE_OUT }
  flow.spinTiming = { duration: 300, easing: EASE_OUT }
  flow.opacityTiming = { duration: 150, easing: 'ease-out' }
  flow.update(from)
  element.replaceChildren(flow)
  requestAnimationFrame(() => {
    flow.update(to)
  })
}

const rollChanged = (before: Counts) =>
  Effect.sync(() => {
    countElements().forEach((element) => {
      const from = before.get(element.dataset['count'] ?? '')
      const to = Number(element.textContent)

      if (from !== undefined && from !== to && !Number.isNaN(from) && !Number.isNaN(to)) {
        roll(element, from, to)
      }
    })
  })

export const mountCounts = Effect.gen(function* () {
  const before = yield* Ref.make<Counts>(NONE)

  yield* Effect.forkScoped(
    Stream.fromEventListener<CustomEvent<SwapDetail>>(document.body, 'htmx:beforeSwap').pipe(
      Stream.runForEach((event) =>
        Ref.set(before, pointerOnSamePage(event.detail) ? readCounts() : NONE),
      ),
    ),
  )
  yield* Effect.forkScoped(
    Stream.fromEventListener(document.body, 'htmx:afterSwap').pipe(
      Stream.runForEach(() => Effect.flatMap(Ref.getAndSet(before, NONE), rollChanged)),
    ),
  )
})
