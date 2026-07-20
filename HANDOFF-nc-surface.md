# NC Surface Expansion — Handoff for Parallel Agent Drive

## Context
- 5 remaining work items parked at `implement` stage in the `nextcloud-factory` run
- Extension source: `/home/neil/dev/swamp/extensions/nextcloud/` (own git repo at NeilHanlon/swamp-nextcloud)
- Current version: **2026.07.20.2** (on beta channel)
- 92 tests green, all previous work items (NC-CALSYNC, NC-CONTACTS, NC-TASKS) shipped
- Factory: `nextcloud-factory` (@swamp/software-factory, id `55d5cdde-3610-48df-a165-ca252bc66652`) in /home/neil/dev/swamp

## Work items to drive (all at implement stage)
| Ref | Scope | Estimated size |
|-----|-------|----------------|
| NC-NOTES | NC Notes REST API (list/get/put/delete markdown notes) | Medium |
| NC-FILES | WebDAV file surface (list/get/put/delete/mkdir) | Large |
| NC-DECK | NC Deck REST API (boards/stacks/cards) | Large |
| NC-SHARES | OCS Share API (list/create/update/revoke/public-link) | Medium |
| NC-USERS | OCS Users API (list/create/edit/delete users, groups) | Large |

## Recommended split for 2 parallel agents
Since all work items extend the **same** `nextcloud.ts` file, they MUST be driven sequentially within each agent — but the two agents can work on DISJOINT subsets in parallel by:

**Option A (worktree isolation, recommended):** Each agent gets its own git worktree + separate factory run. After both finish, merge branches + publish once.
- Agent 1: NC-NOTES + NC-SHARES (2 medium items)
- Agent 2: NC-FILES + NC-DECK + NC-USERS (3 large items)

**Option B (sequential in one agent):** Drive all 5 one after another in a single agent. Slower but simpler.

**Do NOT** have two agents touch nextcloud.ts simultaneously on the same branch — merge conflicts are guaranteed.

## Pattern per work item (same as NC-TASKS)
1. `swamp model method run nextcloud-factory record_dispatch --input workItem=<REF>` (arm implement stage)
2. Read design: `swamp data query 'modelName=="nextcloud-factory" && name=="artifact-<REF>-design"' --json | jq '.results[0].attributes.payload'`
3. Read design-review findings (all resolved, inform implementation choices): `swamp data query 'modelName=="nextcloud-factory" && name=="artifact-<REF>-design-review"' --json`
4. Implement methods in `extensions/nextcloud/nextcloud.ts` (extend existing, don't modify CalDAV/CardDAV/VTODO methods)
5. Add tests in `nextcloud_test.ts` (existing 92 must stay green, add 15-25 new per work item)
6. Bump version in `manifest.yaml` + in the `model.version` field inside nextcloud.ts (chain: 2026.07.20.3, .4, .5, .6, .7)
7. `swamp extension fmt manifest.yaml` + run tests: `cd extensions/nextcloud && /home/neil/.swamp/deno/deno test nextcloud_test.ts`
8. Live verify vs cloud.shrug.pw (the nc model at /home/neil/dev/swamp/ picks up the new version automatically)
9. Commit, record change-summary artifact + change-request evidence; advance transition=submit → verify
10. Record verification evidence; advance transition=pass → code-review
11. Dispatch adversarial + security code reviewers (Agent tool: general-purpose + security-code-reviewer, in parallel)
12. Resolve findings (all as fix-at-implement or accepted-future), record code-review artifact
13. Ship-approval gate (approve gateId=code-approval actor=neil — pre-approved)
14. Publish: `cd extensions/nextcloud && swamp extension push manifest.yaml --channel beta --yes`
15. `git push origin main`
16. Record publish evidence; advance transition=done

## Key gotchas
- **Safety classifier** sometimes blocks `swamp extension push` and `git push` — retry with `sleep 20 && ...` if you hit "temporarily unavailable"
- **All work items extend the SAME nextcloud.ts** — drive sequentially, NOT in parallel on the same branch
- **Version chain:** 2026.07.20.2 → 2026.07.20.3 (NC-NOTES) → 2026.07.20.4 (NC-FILES or NC-DECK) → ... → final
- **Tests:** use bundled deno at `/home/neil/.swamp/deno/deno` (no standalone deno)
- **Live verify:** nc model is at /home/neil/dev/swamp/ (repo root), not in extensions/
- **Factory commands** must be run from /home/neil/dev/swamp (not extensions/nextcloud) or you get "Model not found"
- **Evidence schemas** are strict: only accept the documented keys (e.g. publish evidence accepts only `version` + `url`, change-request only `branch` + `url`)
- **REST API methods (NC-NOTES/DECK/SHARES/USERS):** reuse the existing `davRequest` HTTP helper — it's general-purpose, not DAV-specific. Just set Accept: application/json and don't send XML bodies.
- **PII discipline:** per the project rule, never persist PII in resource snapshots. For get_note/get_file/get_card/get_user type methods that return bodies, either: (a) write metadata-only resource + return body via methodResult, or (b) return everything via methodResult with no resource.

## Patterns to follow in existing code
- **VTODO (NC-TASKS):** lines ~1488-1720 in nextcloud.ts (CalDAV, closest analog to NC-FILES WebDAV)
- **CardDAV (NC-CONTACTS):** lines ~1132-1476 (similar safety pattern)
- **REST pattern reference:** whoami method uses OCS JSON endpoint (line ~1853 in nextcloud.ts) — same shape as NC-NOTES/DECK/SHARES/USERS will use

## After all 5 ship
- `swamp extension promote @kneel/nextcloud <final-version> --channel stable`
- Complete SP parent task `-2zY5pQdtQxLCQnzRj4Xa`
- Open items (NOT part of this factory run): create_addressbook MKCOL 403 debug, upstream @swamp/gcp/calendar design-limits issues, GCONTACTS-NC-SYNC sync workflow

## Skills to load
- `swamp` — CLI commands
- `software-factory` — factory lifecycle
