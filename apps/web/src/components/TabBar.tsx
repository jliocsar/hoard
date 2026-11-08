import { NAV } from '../domain.ts'
import type { EntryType } from '../domain.ts'
import { Icon } from './Icon.tsx'
import type { IconName } from './Icon.tsx'

export type Tab = 'home' | EntryType

export const DOCK = [
  'max-sm:fixed max-sm:inset-x-0 max-sm:bottom-0 max-sm:z-40',
  'max-sm:border-t max-sm:bg-background/90 max-sm:backdrop-blur-md',
  'max-sm:pb-[var(--dock-inset)]',
].join(' ')

const ITEM = [
  'flex h-14 min-w-0 flex-col items-center justify-center gap-1 text-[11px] leading-none font-medium',
  'text-muted-foreground transition-colors active:text-foreground aria-[current=page]:text-foreground',
  'focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring',
].join(' ')

const SHORT = {
  note: 'Notes',
  meeting: 'Meetings',
  task: 'Tasks',
  artifact: 'Artifacts',
} satisfies Record<EntryType, string>

const TabLink = (props: {
  readonly href: string
  readonly icon: IconName
  readonly label: string
  readonly current: boolean
}) => (
  <a class={ITEM} href={props.href} aria-current={props.current ? 'page' : undefined}>
    <Icon name={props.icon} class="size-5" />
    <span class="max-w-full truncate">{props.label}</span>
  </a>
)

export const TabBar = (props: { readonly active: Tab | undefined }) => (
  <nav class={`${DOCK} grid grid-cols-5 sm:hidden`} aria-label="Sections" data-tab-bar>
    <TabLink href="/" icon="home" label="Home" current={props.active === 'home'} />
    {NAV.map((section) => (
      <TabLink
        href={section.path}
        icon={section.type}
        label={SHORT[section.type]}
        current={props.active === section.type}
      />
    ))}
  </nav>
)
