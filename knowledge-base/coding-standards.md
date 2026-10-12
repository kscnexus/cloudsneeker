# Coding Standards

Further Cloudsneeker development uses Prowler's coding style, standards, and structure. The skills under `skills/` and the component `AGENTS.md` files are the source of those rules. This page is the map. Open the skill before changing that area.

## How to Start a Change

1. Find the nearest Prowler file that already does something similar.
2. Read that component's `AGENTS.md` and the skill in the table below.
3. Write a failing test the way that component tests the same kind of change (`skills/tdd/SKILL.md`).
4. Implement only enough to pass, in the same shape as the neighboring file.

## Style by Area

| Area | Structure to copy | Skill |
| --- | --- | --- |
| Security check | `prowler/providers/{provider}/services/{service}/{check_name}/` | `prowler-sdk-check` |
| New provider or service | `prowler/providers/{provider}/` | `prowler-provider` |
| Compliance framework | `prowler/compliance/` | `prowler-compliance` |
| API model, serializer, view | `api/src/backend/api/` | `prowler-api`, `django-drf`, `jsonapi` |
| Celery task | `api/src/backend/tasks/tasks.py` | `prowler-api` |
| UI page or component | `ui/app/(prowler)/` and `ui/components/` | `prowler-ui`, `react-19`, `nextjs-16`, `tailwind-4` |
| UI types | Const object, then derived type, in `ui/types/` | `typescript` |
| Client state | `ui/store/` | `zustand-5` |
| MCP tool | `mcp_server/prowler_mcp_server/` | `prowler-mcp` |
| Tests | Mirror the source tree | `pytest`, `vitest`, `prowler-test-sdk`, `prowler-test-api`, `prowler-test-ui` |

## Standards That Do Not Change in Cloudsneeker Code

Python matches the SDK and API around it: type hints, Google-style docstrings, and the repo formatter.

TypeScript matches the UI: an `as const` object is the source of a type, interfaces stay one level deep, and `any` is not used.

React matches the UI: named React imports, no manual `useMemo` or `useCallback`, a Server Component unless the file needs state or browser APIs, and shared controls from `components/shadcn/`.

API matches `api/src/backend/api/`: UUIDv4 primary keys, tenant row-level security, one serializer each for read, create, and update, and JSON:API responses. Serializers and views do not hold business logic.

A check matches the provider tree: one class subclassing `Check`, a service client singleton, and a metadata JSON file beside the module.

## Where Cloudsneeker Files Still Follow This

`cloudsneeker/`, `api/src/backend/cloudsneeker_api/`, and `ui/app/(cloudsneeker)/` exist so upstream merges stay small. A file inside them is still a Prowler-shaped module. A model there looks like a model in `api/models.py`. A page there looks like a page under `ui/app/(prowler)/`.
