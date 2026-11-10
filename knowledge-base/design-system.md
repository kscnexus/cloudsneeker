# Design System

One visual language for every page of the Cloudsneeker UI, upstream screens included. Started 2026-11-09. The brand stays as set in `product-redesign-plan.md`: signal blue `#2583FF` accent, teal secondary, dense security-dashboard layout. This file is the rulebook; the code is in `ui/cloudsneeker/`.

## How it is built

Upstream files stay mergeable, so the system is three layers that sit on top of them:

| Layer | File | What it does |
| --- | --- | --- |
| Values | `ui/cloudsneeker/theme.css` (`:root`, `.dark`) | Every color, shadow, radius and focus value, for light and dark. |
| Tailwind names | `ui/cloudsneeker/styles/design-tokens.css` (imported by `ui/styles/globals.css`, one hook) | Turns the values into utilities (`bg-bg-info`, `shadow-overlay`, `rounded-surface`, ...) and defines the stock shadcn colors upstream components already use. |
| Surfaces | `ui/cloudsneeker/styles/surfaces.css` (imported first in `theme.css`) | CSS-only restyle of upstream primitives by `data-slot`: tables, dialogs, menus, tabs, labels, cards, focus. |

Cloudsneeker components use the shared building blocks in `ui/cloudsneeker/components/` and class constants in `ui/cloudsneeker/lib/ui-classes.ts`. Never put a hex color or a raw palette class (`text-gray-600`, `bg-red-50`) in a Cloudsneeker component; use a token class.

## Tokens

### Color

| Purpose | Class | Notes |
| --- | --- | --- |
| Page canvas | `bg-bg-neutral-primary` | The `<body>` color. |
| Surface (cards, sidebar, tables) | `bg-bg-neutral-secondary` | |
| Inset / hover / table header | `bg-bg-neutral-tertiary` | Also floating menus. |
| Text | `text-text-neutral-primary`, `-secondary`, `-tertiary` | Primary for values and titles, secondary for body copy, tertiary for help text and captions. |
| Borders | `border-border-neutral-secondary` (default), `-primary`, `-tertiary` (stronger, dashed empty states) | |
| Accent | `bg-button-tertiary`, `text-text-lighthouse`, `bg-sidebar-active-bar` | Signal blue. Active nav item, active tab, selected tile, focus. |
| Success | `bg-bg-pass`, `bg-bg-pass-secondary`, `text-text-success-primary` | |
| Warning | `bg-bg-warning`, `bg-bg-warning-secondary`, `text-text-warning-primary` | |
| Error | `bg-bg-fail`, `bg-bg-fail-secondary`, `text-text-error-primary`, `border-border-error` | |
| Info | `bg-bg-info`, `bg-bg-info-secondary`, `text-text-info-primary`, `border-border-info` | Added 2026-11-09. |
| Severity | `bg-bg-data-critical` ... `bg-bg-data-info` | Finding meaning. Never recolor. |

Stock shadcn names (`text-muted-foreground`, `bg-popover`, `bg-accent`, `text-destructive`, `ring-ring`, `bg-card`, ...) map to the rows above. They exist for upstream code; new Cloudsneeker code uses the product names. `input` is deliberately left undefined (defining it would switch on upstream `dark:bg-input/30` fills).

A few near-miss names that upstream and older Cloudsneeker code used without a token (`text-text-error`, `text-text-info`, `border-border-error-primary`, `text-bg-button-secondary`, ...) are aliased too, so they render. Prefer the canonical name in new code.

### Type

Font: Inter (`--font-sans`), Fira Code for code (`--font-mono`), set in `ui/config/fonts.ts`.

| Role | Classes |
| --- | --- |
| Page title | Navbar (`ContentLayout title`); in-page headings are not repeated. |
| Section title | `text-base font-semibold` (`SectionCard`) |
| In-page heading (optional) | `text-xl font-semibold` (`PageHeader title`) |
| Body | `text-sm` |
| Help text, captions, table header | `text-xs` |
| Eyebrow / KPI label | `text-xs font-medium tracking-wide uppercase` |
| KPI value | `text-2xl font-semibold tabular-nums` |
| Form label | `text-sm` (`FormField`), upstream `field-label` 13px semibold |

Numbers in tables and tiles use `tabular-nums`.

### Spacing

Tailwind's 4px scale. Defaults:

- Page content: `ContentLayout` (`py-4`, navbar above). Sections stack with `gap-6`.
- Section card: header `px-4 py-3 sm:px-5`, body `p-4 sm:p-5`, `gap-3` between items.
- KPI rows: `grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4`.
- Table cells: `px-3 py-2` (Cloudsneeker tables), `0.625rem` vertical (upstream tables via CSS).
- Forms: one column, `max-w-3xl`, `gap-6` between sections, `gap-1.5` label to control.

### Radius, shadow, focus

| Token | Value | Used by |
| --- | --- | --- |
| `--cs-radius-control` / `rounded-control` | 8px | Buttons, inputs, selects, menus, pagination, row-action triggers |
| `--cs-radius-surface` / `rounded-surface` | 12px | Cards, tables, empty states (`rounded-xl` is the same value) |
| `--cs-radius-overlay` / `rounded-overlay` | 16px | Dialogs |
| `--cs-shadow-surface` / `shadow-surface` | 1px hairline | Cards, tables. No large soft shadows on the canvas. |
| `--cs-shadow-overlay` / `shadow-overlay` | Lifted | Dialogs, menus, popovers, skip link |
| `--cs-focus-ring` | Signal blue | Default `:focus-visible` outline (base layer); `FOCUS_RING_CLASS` for links and tiles |

## Components

Use these instead of building a new variant:

| Need | Component |
| --- | --- |
| Page intro, record facts, page actions | `PageHeader` (`description`, `meta`, `actions`) |
| Labelled block on a page | `SectionCard` |
| KPI | `StatTile` (tone, link, selected) |
| Severity proportion + drill-down | `SeverityBreakdown` |
| Nothing to show | `EmptyState` (icon, title, one-line description, optional action) |
| Error from an action or a load | `FormAlert` (`role="alert"`) |
| Form layout | `FormField`, `FormChoiceGroup`, `FormActions` (`form-layout.tsx`) |
| Run / job state | `RunStatusBadge` |
| Plain data table | `TABLE_FRAME_CLASS`, `TABLE_CLASS`, `TABLE_HEAD_CLASS`, `TABLE_HEADER_CELL_CLASS`, `TABLE_BODY_CLASS` |
| Upstream list with filters, sorting, paging | shadcn `DataTable` (restyled by `surfaces.css`) |
| Detail of a row | Side sheet (`components/shadcn/sheet`), not a new route |
| Buttons, inputs, selects, dialogs, tabs, tooltips, badges | `components/shadcn/*` |

Buttons: `default` (primary, one per view), `outline` (secondary), `ghost` (tertiary, toolbar), `destructive` (with a confirmation dialog). Sizes `sm` in headers and tables, `default` in forms.

## Patterns

- **List pages**: `PageHeader` (description, primary action) -> KPI row -> filters -> table -> pagination. Empty list: `EmptyState` with the action that fills it.
- **Detail pages**: `PageHeader` with `meta` (status, owner, dates) and actions (primary right-most), then `SectionCard`s.
- **Forms**: `SectionCard` per group, help under the control, field errors under the field with `role="alert"`, the save error in `FormAlert` above `FormActions`. Disable submit while pending.
- **Status**: always a word plus color (badge text, icon, or label). Never color alone.
- **Destructive actions**: confirmation dialog naming the thing being deleted.
- **Loading**: `Skeleton` in the shape of the content; `AutoRefresh` for queued jobs.

## Accessibility

- Every signed-in page starts with a "Skip to content" link (`SkipToContent`) that focuses `<main>`.
- Visible focus on every control: components draw their own ring; anything else gets the base `:focus-visible` outline.
- Errors and results of actions use `role="alert"` (`FormAlert`, `FieldError`).
- `prefers-reduced-motion` turns off transitions.
- Text tokens meet 4.5:1 on every neutral surface in both themes. The lowest pair is light tertiary text (`#536a76`) on the tag background, 4.85:1; it was `#5c7380` (4.45:1 on the canvas) until 2026-11-09. The focus ring is 4.4:1 (light) and 9.3:1 (dark) against the canvas, above the 3:1 for non-text.

## Responsive

- Sidebar is fixed from 64rem (`lg`); below, the mobile sheet sidebar.
- Tables scroll inside their own frame; the page never scrolls sideways.
- Dialogs fit 375px (`max-height: calc(100dvh - 2rem)`, inner scroll) and button rows wrap.
- KPI grids go 1 -> 2 -> 4 columns (`sm`, `xl`); `PageHeader` actions wrap under the description on phones.

## Not covered yet

- Upstream components that hard-code palette classes outside a `data-slot` (for example the overview time-range selector's green underline, some lighthouse-v1 chat elements) keep their colors.
- The legacy `components/ui/*` shims (old dialog, dropdown, button) are upstream files; they pick up the shadcn aliases but are not merged into `components/shadcn/`.
