# Cloudsneeker Extensions

Python code that belongs only to Cloudsneeker lives in this directory. It imports the `prowler` package and does not replace it. Modules here follow the same style as `prowler/`: type hints, Google docstrings, and the same test layout. See `knowledge-base/coding-standards.md`.

Upstream Prowler merges leave this directory alone. API additions go in `api/src/backend/cloudsneeker_api/`. New screens go in `ui/app/(cloudsneeker)/`. The rules for that split are in `knowledge-base/upstream-sync.md`.
