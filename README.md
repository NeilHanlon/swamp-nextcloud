# @kneel/nextcloud

Drive a [Nextcloud](https://nextcloud.com/) instance from
[swamp](https://github.com/swamp-club/swamp) over its CalDAV / WebDAV / OCS
surfaces using an **app-password** (HTTP Basic) credential.

The model's first job is **event-level calendar sync**: upsert real VEVENTs
(keyed by `iCalUID`) into a Nextcloud calendar so a source calendar — e.g. a
Google calendar read by [`@swamp/gcp/calendar`](https://swamp-club.com) — shows
up as editable native events that propagate to every CalDAV client, with swamp
in the data path.

## Why app passwords (not the web import route)

Nextcloud's `integration_google` "import calendar" button is a CSRF-protected,
session-bound AJAX endpoint — it cannot be replayed with a static credential. An
app password authenticates cleanly against `/remote.php/dav` (CalDAV/WebDAV) and
`/ocs/v2.php` (OCS, with `OCS-APIRequest: true`) and is exempt from that CSRF
wall, so a proper API model is the right shape.

## Methods

| Method | What it does |
| --- | --- |
| `whoami` | Verify app-password auth via OCS `cloud/user`; record `{userId, displayName, email}`. |
| `list_calendars` | PROPFIND the calendar home; record `{displayName, path, color, hasSource}`. Subscription source URLs are **masked**. |
| `put_events` | Fan-out CalDAV `PUT` of VEVENTs keyed by `iCalUID` (idempotent upsert). |
| `delete_events` | Fan-out verify-then-`DELETE` by `iCalUID` (idempotent). |

### `put_events` input

`events[]` is a subset of the `@swamp/gcp/calendar/events` resource shape, so a
sync workflow can pass Google events through with minimal remapping:

```jsonc
{
  "uid": "abc123@google.com",   // iCalUID — the upsert key
  "summary": "Standup",
  "description": "…",            // optional
  "location": "…",              // optional
  "start": { "dateTime": "2026-07-17T09:00:00-04:00" },  // or { "date": "2026-07-17" }
  "end":   { "dateTime": "2026-07-17T09:30:00-04:00" },
  "status": "confirmed",         // or "cancelled" → STATUS:CANCELLED
  "recurrence": ["RRULE:FREQ=WEEKLY;BYDAY=MO"]           // optional
}
```

Timed events are normalized to UTC (`…Z`), so no `VTIMEZONE` blocks are emitted.
All-day events (`date`) become `VALUE=DATE`.

## Security

- **`appPassword` is a sensitive global argument** — wire it to a vault at
  model-create time, never inline it.
- **`baseUrl` must be `https://`** — Basic auth sends `base64(user:appPassword)`
  that is only protected by TLS. The schema rejects `http://`.
- The `Authorization` header is **never logged**; event PII
  (SUMMARY/DESCRIPTION/LOCATION/raw VEVENT bodies) is **never logged and never
  persisted** in resource snapshots — resources carry only UIDs and per-item
  outcomes.
- Nextcloud brute-force protection counts Basic-auth attempts and can
  progressively delay a busy IP even with valid credentials. Keep call volume
  low (the fan-out methods make one dispatch per batch) or allowlist the swamp
  host.

## Quickstart

```bash
# 1. store the app password in a vault (hidden prompt)
swamp vault put nextcloud appPassword

# 2. create the model, wiring the sensitive arg from the vault
swamp model create @kneel/nextcloud nc \
  --global-arg baseUrl=https://cloud.example.com \
  --global-arg username=neil \
  --global-arg appPassword='${{ vault.get(nextcloud, appPassword) }}'

swamp model method run nc whoami                          # auth proof
swamp model method run nc list_calendars                  # discover target calendar
swamp model method run nc put_events \
  --input calendar=personal \
  --input-json events='[{"uid":"x@google.com","summary":"Hi","start":{"dateTime":"2026-07-17T09:00:00Z"},"end":{"dateTime":"2026-07-17T09:30:00Z"}}]'
```

## Event-level Google → Nextcloud sync

Read the Google side with `@swamp/gcp/calendar/events` (a service account with
the target calendar **shared** to it) and pipe the events into `put_events` via
a swamp workflow. Deletions removed from Google are propagated with
`delete_events`. A CalDAV webcal *subscription* is a possible post-release
fallback (zero Google auth, but read-only in Nextcloud and keeps swamp out of
the data path) — event-level sync is the primary design.

## Development

```bash
DENO=~/.swamp/deno/deno
$DENO check nextcloud.ts nextcloud_test.ts
$DENO test  nextcloud_test.ts
```

## License

MIT © Neil Hanlon
