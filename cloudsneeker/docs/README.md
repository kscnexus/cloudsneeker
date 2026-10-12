# Cloudsneeker documentation site

Client-facing docs served at `brand.docs_url`. Built with [Mintlify](https://mintlify.com); `docs.json` is the site configuration. Upstream `docs/` stays untouched and is not published.

## Build

Check pages and the CloudFormation template are generated, not committed:

```shell
python cloudsneeker/tools/gen_check_docs.py   # writes checks/*.mdx, templates/, and the Checks tab of docs.json
npx mint dev --dir cloudsneeker/docs           # or `mint build` in CI
```

The generator:

- Writes one `checks/{check_id}.mdx` per check id from `prowler/providers/*/services/*/*/*.metadata.json`. A check id implemented by several providers gets one page with a section per provider, because findings link with the id alone (`brand.check_docs_url`).
- Writes `checks/index.mdx` and rewrites the `Checks` tab of `docs.json` grouped by provider and service.
- `docs.json` `redirects` serve the documentation paths the web app links to (`user-guide/providers/...`, `user-guide/tutorials/...`). `tests/cloudsneeker/docs_links_test.py` checks every `docsUrl(...)` call in the UI against the pages and redirects; add a redirect when the UI gains a new help link.
- Writes one `compliance/{framework_id}.mdx` per file under `prowler/compliance/` (per-provider and cross-provider schemas) with every requirement linked to its checks, plus `compliance/index.mdx` and the `Frameworks` tab. The web app's compliance pages link to `{docs_url}/compliance/{framework_id}`.
- Publishes `templates/cloudsneeker-scan-role.yml`, the upstream CloudFormation template run through `cloudsneeker/tools/rebrand.rules.toml`, so `brand.cloudformation_template_url` resolves.

Run `python cloudsneeker/tools/brand_audit.py --tree cloudsneeker/docs` after generating; it must report zero hits.

`git checkout cloudsneeker/docs/docs.json` restores the minimal committed navigation after a local build.

## Writing pages

- Product name is `Cloudsneeker`; never name the upstream project or link to its sites.
- Brand URLs (`cloudsneeker.example`) are placeholders until the production domains exist; they are the same values as `cloudsneeker/brand.py` and `ui/cloudsneeker/brand.ts`.
- Describe only behavior that exists in this edition. Hosted-only features of the upstream product (Slack in-app, advanced schedules, Lighthouse) are not documented.
- Use Mintlify components (`Steps`, `Tabs`, `Card`, `Columns`) as the existing pages do. Escape `{`, `}`, and `<` in prose.
