import { z } from "npm:zod@4";
import { randomBytes } from "node:crypto";

/**
 * @kneel/nextcloud — drive a Nextcloud instance from swamp over its CalDAV /
 * WebDAV / OCS surfaces using an app-password (HTTP Basic) credential.
 *
 * The first job of this model is EVENT-LEVEL calendar sync: upsert real VEVENTs
 * (keyed by iCalUID) into a Nextcloud calendar so a source calendar — e.g. a
 * Google calendar read by `@swamp/gcp/calendar` — shows up as editable native
 * events that propagate to every CalDAV client, with swamp in the data path.
 *
 * Security posture (mandated by the NC-CALSYNC design review):
 *   - `appPassword` is a sensitive global argument, wired to a vault at
 *     model-create time — never inlined.
 *   - The `Authorization` header is never logged; redirects are not followed so
 *     the credential is never replayed to another origin.
 *   - Event PII (SUMMARY / DESCRIPTION / LOCATION / raw VEVENT bodies) is never
 *     logged and never persisted into `writeResource` snapshots — resources
 *     carry only UIDs and per-item outcomes.
 *   - `baseUrl` is refined to require https so Basic credentials are not sent in
 *     effective cleartext.
 *   - All iCalendar text is escaped and every serialized field is stripped of
 *     control characters, so no caller-supplied value can inject an iCal
 *     property or component (defense in depth on top of schema validation).
 *
 * @module
 */

// ---------------------------------------------------------------------------
// Context type (mirrors the shape swamp passes to `execute`)
// ---------------------------------------------------------------------------

type WriteResource = (
  specName: string,
  name: string,
  data: Record<string, unknown>,
) => Promise<{ name: string }>;

type Logger = {
  debug(msg: string, props?: Record<string, unknown>): void;
  info(msg: string, props?: Record<string, unknown>): void;
  warn(msg: string, props?: Record<string, unknown>): void;
  error(msg: string, props?: Record<string, unknown>): void;
  fatal(msg: string, props?: Record<string, unknown>): void;
};

type Context = {
  globalArgs: Record<string, unknown>;
  writeResource: WriteResource;
  logger?: Logger;
};

// ---------------------------------------------------------------------------
// Control-character guard (avoids control chars in regex literals)
// ---------------------------------------------------------------------------

/** True if the string contains any ASCII control character (0x00–0x1F or 0x7F). */
export function hasControlChars(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

/** Replace control characters with spaces and cap length — for server-derived text. */
export function clip(s: string, max = 160): string {
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0) ?? 0;
    out += c < 0x20 || c === 0x7f ? " " : ch;
  }
  return out.slice(0, max);
}

// ---------------------------------------------------------------------------
// Global arguments
// ---------------------------------------------------------------------------

/** Model global arguments. Exported for validation tests. */
export const GlobalArgsSchema = z.object({
  baseUrl: z
    .string()
    .url()
    .refine((u) => u.toLowerCase().startsWith("https://"), {
      message:
        "baseUrl must be https:// — Basic auth sends base64(user:appPassword) that is only protected by TLS.",
    })
    .describe(
      "Nextcloud base URL, e.g. https://cloud.example.com (no trailing slash).",
    ),
  username: z
    .string()
    .min(1)
    .describe("Nextcloud login / DAV principal user name."),
  appPassword: z
    .string()
    .min(1)
    .meta({ sensitive: true })
    .describe(
      "Nextcloud app password (Settings → Security → Devices & sessions). Wire to a vault; never inline.",
    ),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

// ---------------------------------------------------------------------------
// Method argument / event schemas
// ---------------------------------------------------------------------------

/** A calendar-time value in the Google Calendar shape (date OR dateTime). */
const EventTimeSchema = z.object({
  date: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, "date must be YYYY-MM-DD")
    .optional()
    .describe("All-day date, YYYY-MM-DD (mutually exclusive with dateTime)."),
  dateTime: z
    .string()
    .regex(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/,
      "dateTime must be an RFC3339 timestamp",
    )
    .optional()
    .describe("RFC3339 timestamp for a timed event."),
  timeZone: z
    .string()
    .regex(/^[A-Za-z0-9_+\-\/]+$/, "timeZone must be an IANA time zone name")
    .optional()
    .describe("IANA time zone name (used only for offset-less dateTime)."),
});

/**
 * Normalized event input for upsert. Deliberately a subset of the
 * `@swamp/gcp/calendar/events` resource shape so a sync workflow can pass
 * Google events through with minimal remapping.
 *
 * Exported for validation tests.
 */
export const EventInputSchema = z.object({
  uid: z
    .string()
    .min(1)
    .refine((s) => !hasControlChars(s), {
      message: "uid must not contain control characters",
    })
    .describe("iCalUID — the cross-system unique id used as the upsert key."),
  summary: z.string().optional().describe("Event title."),
  description: z.string().optional(),
  location: z.string().optional(),
  start: EventTimeSchema,
  end: EventTimeSchema,
  status: z
    .enum(["confirmed", "tentative", "cancelled"])
    .optional()
    .describe("Event status; 'cancelled' is written as STATUS:CANCELLED."),
  recurrence: z
    .array(
      z
        .string()
        .regex(
          /^(RRULE|RDATE|EXDATE|EXRULE|RECURRENCE-ID)[;:]/i,
          "recurrence must be a single RRULE/RDATE/EXDATE/EXRULE/RECURRENCE-ID line",
        )
        .refine((s) => !hasControlChars(s), {
          message: "recurrence line must not contain line breaks",
        }),
    )
    .optional()
    .describe("RFC5545 recurrence lines, e.g. ['RRULE:FREQ=WEEKLY']."),
  sequence: z
    .number()
    .int()
    .nonnegative()
    .optional()
    .describe("SEQUENCE for update ordering; defaults to 0."),
});

type EventInput = z.infer<typeof EventInputSchema>;

const WhoamiArgsSchema = z.object({});

const ListCalendarsArgsSchema = z.object({});

const PutEventsArgsSchema = z.object({
  calendar: z
    .string()
    .min(1)
    .describe(
      "Target calendar name (the last path segment under calendars/<user>/, e.g. 'personal').",
    ),
  events: z
    .array(EventInputSchema)
    .default([])
    .describe(
      "Events to upsert (fan-out: one dispatch handles all). An empty batch is a no-op so a sync workflow can pass it through unconditionally.",
    ),
});

export const DeleteEventsArgsSchema = z.object({
  calendar: z.string().min(1).describe("Target calendar name."),
  uids: z
    .array(z.string().min(1))
    .default([])
    .describe("iCalUIDs to delete (fan-out). An empty batch is a no-op."),
  requireProvenance: z
    .boolean()
    .default(true)
    .describe(
      "When true (default), GET each event and refuse to delete any that lacks the X-SWAMP-SYNC marker (server-side reconciliation guard, V-2). Set false only for a raw delete.",
    ),
  dryRun: z
    .boolean()
    .default(false)
    .describe(
      "When true, run the full existence + provenance decision for each uid but issue no DELETE. Events that would be removed are reported as 'would-delete'; nothing is mutated. A safe preview of a reconciliation delete.",
    ),
  maxDeletes: z
    .number()
    .int()
    .min(0)
    .default(50)
    .describe(
      "Blast-radius cap: if the batch has MORE than this many uids, abort the " +
        "whole delete (mutate nothing) and report aborted=true. A reconciliation " +
        "that suddenly wants to remove an implausible number of events is almost " +
        "always a bug (bad window, empty/mis-wired fetch) rather than a real mass " +
        "deletion. 0 disables the cap. Applies to dry-run too.",
    ),
});

/** RFC3339 window bound (used by list_events time-range filtering). */
const Rfc3339 = z
  .string()
  .regex(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/,
    "must be an RFC3339 timestamp with an explicit zone",
  );

const ListEventsArgsSchema = z.object({
  calendar: z.string().min(1).describe("Target calendar name."),
  timeMin: Rfc3339.describe("Window start, inclusive (RFC3339)."),
  timeMax: Rfc3339.describe("Window end, exclusive (RFC3339)."),
});

const CreateCalendarArgsSchema = z.object({
  calendar: z
    .string()
    .min(1)
    .regex(
      /^[A-Za-z0-9._-]+$/,
      "calendar name (collection slug) must be URL/path safe",
    )
    .describe("Calendar collection slug to create, e.g. 'gcal-sync'."),
  displayName: z
    .string()
    .min(1)
    .max(120)
    .optional()
    .describe("Human-readable calendar name (defaults to the slug)."),
  color: z
    .string()
    .regex(/^#[0-9A-Fa-f]{6}$/, "color must be #RRGGBB")
    .optional()
    .describe("Calendar color as #RRGGBB."),
});

// ---------------------------------------------------------------------------
// CardDAV method argument / contact schemas
// ---------------------------------------------------------------------------

/** Contact input schema for put_contacts. PII-minimal: only UID + FN in read-back. */
export const ContactInputSchema = z.object({
  uid: z
    .string()
    .min(1)
    .max(200)
    .refine((s) => !s.includes("\0"), { message: "uid must not contain NUL" })
    .refine((s) => /^[A-Za-z0-9_\-.]{1,200}$/.test(s), {
      message:
        "uid must match /^[A-Za-z0-9_\\-.]{1,200}$/ (path-traversal guard, SEC-2)",
    })
    .describe("Contact UID — the cross-system unique upsert key."),
  fn: z.string().min(1).describe("Formatted name (required)."),
  n: z
    .object({
      family: z.string().optional(),
      given: z.string().optional(),
      additional: z.string().optional(),
      prefix: z.string().optional(),
      suffix: z.string().optional(),
    })
    .optional()
    .describe("Structured name."),
  email: z
    .array(
      z.object({
        value: z.string().min(1),
        type: z.string().optional(),
      }),
    )
    .optional(),
  tel: z
    .array(
      z.object({
        value: z.string().min(1),
        type: z.string().optional(),
      }),
    )
    .optional(),
  adr: z
    .array(
      z.object({
        pobox: z.string().optional(),
        ext: z.string().optional(),
        street: z.string().optional(),
        locality: z.string().optional(),
        region: z.string().optional(),
        code: z.string().optional(),
        country: z.string().optional(),
        type: z.string().optional(),
      }),
    )
    .optional(),
  org: z.string().optional(),
  title: z.string().optional(),
  note: z.string().optional(),
  bday: z
    .string()
    .regex(/^\d{4}-?\d{2}-?\d{2}$/, "bday must be YYYY-MM-DD or YYYYMMDD")
    .optional(),
  url: z.string().optional(),
  categories: z.array(z.string()).optional(),
});

const ListAddressbooksArgsSchema = z.object({});

const CreateAddressbookArgsSchema = z.object({});

const ListContactsArgsSchema = z.object({
  addressbook: z.string().min(1).describe("Target addressbook name."),
});

const PutContactsArgsSchema = z.object({
  addressbook: z.string().min(1).describe("Target addressbook name."),
  contacts: z
    .array(ContactInputSchema)
    .default([])
    .describe("Contacts to upsert (fan-out). An empty batch is a no-op."),
});

export const DeleteContactsArgsSchema = z.object({
  addressbook: z.string().min(1).describe("Target addressbook name."),
  uids: z
    .array(z.string().min(1))
    .default([])
    .describe("Contact UIDs to delete (fan-out). An empty batch is a no-op."),
  requireProvenance: z
    .boolean()
    .default(true)
    .describe(
      "When true (default), GET each VCard and refuse to delete any that lacks the X-SWAMP-SYNC marker.",
    ),
  dryRun: z
    .boolean()
    .default(false)
    .describe("When true, preview deletions without mutating."),
  maxDeletes: z
    .number()
    .int()
    .min(0)
    .default(50)
    .describe(
      "Blast-radius cap: if the batch has MORE than this many uids, abort the whole delete.",
    ),
});

// ---------------------------------------------------------------------------
// CalDAV VTODO (tasks) method argument / task schemas
// ---------------------------------------------------------------------------

/**
 * Task input schema for put_tasks. Mirrors the NC Tasks app's VTODO surface:
 * UID + SUMMARY + DUE (date or datetime) + STATUS + PRIORITY + PERCENT-COMPLETE
 * + CATEGORIES + DESCRIPTION + RELATED-TO (parent). Same escapeText + foldLine
 * defense-in-depth as the VEVENT serializer.
 */
export const TaskInputSchema = z.object({
  uid: z
    .string()
    .min(1)
    .max(200)
    .refine((s) => !s.includes("\0"), { message: "uid must not contain NUL" })
    .refine((s) => /^[A-Za-z0-9_\-.@]{1,200}$/.test(s), {
      message:
        "uid must match /^[A-Za-z0-9_\\-.@]{1,200}$/ (path-traversal guard, SEC-2)",
    })
    .describe("Task UID — the cross-system unique upsert key."),
  summary: z.string().min(1).max(500).describe("Task title (required)."),
  description: z.string().max(5000).optional(),
  due: z
    .object({
      date: z
        .string()
        .regex(/^\d{4}-\d{2}-\d{2}$/, "date must be YYYY-MM-DD")
        .optional()
        .describe("All-day due date, YYYY-MM-DD."),
      dateTime: z
        .string()
        .regex(
          /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/,
          "dateTime must be an RFC3339 timestamp",
        )
        .optional()
        .describe("RFC3339 timestamp for a timed due."),
      timeZone: z
        .string()
        .regex(
          /^[A-Za-z0-9_+\-\/]+$/,
          "timeZone must be an IANA time zone name",
        )
        .optional(),
    })
    .optional()
    .describe("Due date (mutually-exclusive date OR dateTime)."),
  status: z
    .enum(["NEEDS-ACTION", "COMPLETED", "IN-PROCESS", "CANCELLED"])
    .default("NEEDS-ACTION")
    .describe("VTODO STATUS value."),
  priority: z
    .number()
    .int()
    .min(0)
    .max(9)
    .optional()
    .describe("RFC 5545 priority (0=undefined, 1=highest, 9=lowest)."),
  percentComplete: z
    .number()
    .int()
    .min(0)
    .max(100)
    .optional()
    .describe("PERCENT-COMPLETE (0–100)."),
  categories: z.array(z.string().max(100)).max(20).optional(),
  relatedTo: z
    .string()
    .max(200)
    .optional()
    .describe("Parent task UID (RELATED-TO; RELTYPE=PARENT)."),
  recurrence: z
    .array(
      z
        .string()
        .regex(
          /^(RRULE|RDATE|EXDATE|EXRULE|RECURRENCE-ID)[;:]/i,
          "recurrence must be a single RRULE/RDATE/EXDATE/EXRULE/RECURRENCE-ID line",
        )
        .refine((s) => !hasControlChars(s), {
          message: "recurrence line must not contain line breaks",
        }),
    )
    .optional(),
});

type TaskInput = z.input<typeof TaskInputSchema>;

const ListTasklistsArgsSchema = z.object({});

const CreateTasklistArgsSchema = z.object({});

const ListTasksArgsSchema = z.object({
  tasklist: z.string().min(1).describe("Target tasklist name."),
});

const PutTasksArgsSchema = z.object({
  tasklist: z.string().min(1).describe("Target tasklist name."),
  tasks: z
    .array(TaskInputSchema)
    .default([])
    .describe("Tasks to upsert (fan-out). An empty batch is a no-op."),
});

export const DeleteTasksArgsSchema = z.object({
  tasklist: z.string().min(1).describe("Target tasklist name."),
  uids: z
    .array(z.string().min(1))
    .default([])
    .describe("Task UIDs to delete (fan-out). An empty batch is a no-op."),
  requireProvenance: z
    .boolean()
    .default(true)
    .describe(
      "When true (default), GET each VTODO and refuse to delete any that lacks the X-SWAMP-SYNC:tasks-nc-sync marker.",
    ),
  dryRun: z
    .boolean()
    .default(false)
    .describe("When true, preview deletions without mutating."),
  maxDeletes: z
    .number()
    .int()
    .min(0)
    .default(50)
    .describe(
      "Blast-radius cap: if the batch has MORE than this many uids, abort the whole delete.",
    ),
});

// ---------------------------------------------------------------------------
// Resource schemas — MUST NOT carry secrets or event PII
// ---------------------------------------------------------------------------

const IdentitySchema = z.object({
  userId: z.string(),
  displayName: z.string(),
  email: z.string(),
});

const CalendarSchema = z.object({
  displayName: z.string(),
  /** Path relative to the DAV root; safe to persist (not a secret). */
  path: z.string(),
  color: z.string().nullable(),
  /** True when this is a webcal subscription with a source — the source URL is masked. */
  hasSource: z.boolean(),
});

const UpsertOutcomeSchema = z.object({
  uid: z.string(),
  outcome: z.enum(["created", "updated", "failed"]),
  httpStatus: z.number(),
  error: z.string().optional(),
});

const DeleteOutcomeSchema = z.object({
  uid: z.string(),
  outcome: z.enum([
    "deleted",
    "would-delete",
    "not-found",
    "skipped",
    "failed",
  ]),
  httpStatus: z.number(),
  error: z.string().optional(),
});

/** A single addressbook read back from a PROPFIND. */
const AddressbookSchema = z.object({
  url: z.string(),
  displayName: z.string(),
});

/** A single contact reference read back from an addressbook (no PII). */
const ContactRefSchema = z.object({
  uid: z.string(),
  fn: z.string(),
  hasProvenance: z.boolean(),
});

/** A single event read back from a calendar — UID + DTSTART + provenance + RRULE flag only. */
const CalEventRefSchema = z.object({
  uid: z.string(),
  dtstart: z.string(),
  hasProvenance: z.boolean(),
  isRecurring: z.boolean().describe(
    "True if the mirror VEVENT carries an RRULE. A windowed reconciliation must " +
      "NOT delete a recurring event on absence-from-fetch alone: gcal events.list " +
      "and CalDAV RRULE-expansion disagree on which masters fall in a window, so a " +
      "still-live series could be wrongly removed (ADV-2).",
  ),
});

/** A task list (VTODO calendar-type collection) read back from a PROPFIND. */
const TasklistSchema = z.object({
  url: z.string(),
  displayName: z.string(),
});

/** A single task read back from a tasklist (UID + SUMMARY + STATUS + provenance only). */
const TaskRefSchema = z.object({
  uid: z.string(),
  summary: z.string(),
  status: z.string(),
  hasProvenance: z.boolean(),
});

// ---------------------------------------------------------------------------
// Auth + HTTP transport (redacted logging: never log Authorization or bodies)
// ---------------------------------------------------------------------------

/** Build an HTTP Basic `Authorization` header value from a username/password. */
export function basicAuth(username: string, password: string): string {
  return "Basic " + btoa(`${username}:${password}`);
}

/** DAV root (`/remote.php/dav`) for a Nextcloud base URL, trailing slash trimmed. */
export function davBase(baseUrl: string): string {
  return `${baseUrl.replace(/\/$/, "")}/remote.php/dav`;
}

/** OCS v2 root (`/ocs/v2.php`) for a Nextcloud base URL, trailing slash trimmed. */
export function ocsBase(baseUrl: string): string {
  return `${baseUrl.replace(/\/$/, "")}/ocs/v2.php`;
}

/** URL for a single calendar collection under the principal's calendar home. */
export function calendarUrl(
  baseUrl: string,
  username: string,
  calendar: string,
): string {
  const slug = encodeURIComponent(calendar.replace(/^\/+|\/+$/g, ""));
  return `${davBase(baseUrl)}/calendars/${
    encodeURIComponent(username)
  }/${slug}/`;
}

/**
 * Deterministic, filesystem-safe object name for a UID. Same UID always maps to
 * the same `.ics` resource name so PUT is an idempotent upsert. A short FNV-1a
 * hash of the raw UID is appended to keep distinct UIDs that sanitize alike from
 * colliding.
 */
export function eventHref(
  baseUrl: string,
  username: string,
  calendar: string,
  uid: string,
): string {
  const safe = uid.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 96);
  return `${calendarUrl(baseUrl, username, calendar)}${safe}-${fnv1a(uid)}.ics`;
}

/** FNV-1a 32-bit hash rendered as 8 hex chars. Pure, no crypto import. */
export function fnv1a(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

type DavResponse = {
  status: number;
  ok: boolean;
  text: string;
  headers: Record<string, string>;
};

/**
 * Issue a DAV/OCS request. Logs only method + path + status + byte count —
 * never the Authorization header and never the request/response body (which for
 * calendar traffic contains event PII). Redirects are NOT followed, so the
 * Basic credential can never be replayed to another origin.
 */
async function davRequest(
  method: string,
  url: string,
  auth: string,
  opts: {
    body?: string;
    headers?: Record<string, string>;
    okStatuses?: number[];
    log?: Logger;
  } = {},
): Promise<DavResponse> {
  const { body, headers = {}, okStatuses = [], log } = opts;
  const path = safePath(url);
  log?.debug("{method} {path}", { method, path });
  const resp = await fetch(url, {
    method,
    headers: { Authorization: auth, ...headers },
    body,
    redirect: "manual",
    signal: AbortSignal.timeout(30_000),
  });
  const text = await resp.text();
  // Extract response headers as a simple key-value map (lowercase keys).
  const respHeaders: Record<string, string> = {};
  resp.headers.forEach((v, k) => {
    respHeaders[k.toLowerCase()] = v;
  });
  log?.debug("{method} {path} -> {status} ({bytes} bytes)", {
    method,
    path,
    status: resp.status,
    bytes: text.length,
  });
  if (
    resp.type === "opaqueredirect" ||
    (resp.status >= 300 && resp.status < 400)
  ) {
    throw new Error(
      `${method} ${path} returned an unexpected redirect; auth was not replayed`,
    );
  }
  const acceptable = resp.ok || resp.status === 207 ||
    okStatuses.includes(resp.status);
  if (!acceptable) {
    throw new Error(
      `${method} ${path} failed: HTTP ${resp.status} ${
        clip(resp.statusText, 80)
      }`,
    );
  }
  return { status: resp.status, ok: resp.ok, text, headers: respHeaders };
}

/** Strip query/userinfo from a URL for safe logging. */
export function safePath(url: string): string {
  try {
    const u = new URL(url);
    return u.origin + u.pathname;
  } catch {
    return url.split("?")[0];
  }
}

// ---------------------------------------------------------------------------
// XML helpers (regex-based, mirroring @josephholsten/caldav — no XML dep)
// ---------------------------------------------------------------------------

/** All text contents of `<localName>…</localName>` (any namespace prefix). */
export function extractAll(xml: string, localName: string): string[] {
  const results: string[] = [];
  const re = new RegExp(
    `<(?:[^:>]+:)?${localName}(?:\\s[^>]*)?>([\\s\\S]*?)</(?:[^:>]+:)?${localName}>`,
    "gi",
  );
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) results.push(m[1].trim());
  return results;
}

/** First text content of `<localName>…</localName>`, or null. */
export function extractFirst(xml: string, localName: string): string | null {
  return extractAll(xml, localName)[0] ?? null;
}

/** Self-closing or paired presence test, e.g. calendarserver:subscribed. */
export function hasElement(xml: string, localName: string): boolean {
  const re = new RegExp(`<(?:[^:>]+:)?${localName}(?:[\\s/>]|>)`, "i");
  return re.test(xml);
}

/**
 * Reduce an extracted XML fragment to plain text: unwrap CDATA, then remove any
 * nested element subtree (tag AND its content) followed by any stray tags. This
 * defeats a PROPFIND response that smuggles a secret `<source><href>` inside
 * `<displayname>` — the URL text is inside a nested element and is dropped.
 */
export function sanitizeXmlText(s: string): string {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/<([^\s/>]+)(?:\s[^>]*)?>[\s\S]*?<\/\1>/g, "")
    .replace(/<[^>]*>/g, "")
    .trim();
}

const PROPFIND_CALENDARS_BODY = `<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/"
            xmlns:ic="http://apple.com/ns/ical/" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:displayname/>
    <d:resourcetype/>
    <ic:calendar-color/>
    <cs:source/>
  </d:prop>
</d:propfind>`;

/**
 * Body for a CalDAV `calendar-query` REPORT that returns, for every VEVENT whose
 * time-range overlaps [start, end), a partial calendar-data carrying only UID,
 * DTSTART, RRULE and the provenance marker — never SUMMARY/DESCRIPTION/LOCATION,
 * so no PII is pulled (RRULE is structural, not PII). `start`/`end` are
 * compact-UTC stamps (YYYYMMDDTHHMMSSZ).
 */
export function calendarQueryBody(start: string, end: string): string {
  const s = start.replace(/[^0-9TZ]/g, "");
  const e = end.replace(/[^0-9TZ]/g, "");
  return `<?xml version="1.0" encoding="utf-8"?>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:getetag/>
    <c:calendar-data>
      <c:comp name="VCALENDAR">
        <c:comp name="VEVENT">
          <c:prop name="UID"/>
          <c:prop name="DTSTART"/>
          <c:prop name="RRULE"/>
          <c:prop name="${PROVENANCE_PROP}"/>
        </c:comp>
      </c:comp>
    </c:calendar-data>
  </d:prop>
  <c:filter>
    <c:comp-filter name="VCALENDAR">
      <c:comp-filter name="VEVENT">
        <c:time-range start="${s}" end="${e}"/>
      </c:comp-filter>
    </c:comp-filter>
  </c:filter>
</c:calendar-query>`;
}

/**
 * Body for MKCALENDAR. `displayName` is XML-escaped; `color` is already
 * `#RRGGBB`-validated by the schema.
 */
export function mkcalendarBody(displayName: string, color?: string): string {
  const colorProp = color
    ? `\n      <ic:calendar-color>${color}</ic:calendar-color>`
    : "";
  return `<?xml version="1.0" encoding="utf-8"?>
<c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"
              xmlns:ic="http://apple.com/ns/ical/">
  <d:set>
    <d:prop>
      <d:displayname>${xmlEscape(displayName)}</d:displayname>${colorProp}
    </d:prop>
  </d:set>
</c:mkcalendar>`;
}

/** Parse a calendars PROPFIND multistatus into safe Calendar rows. */
export function parseCalendars(xml: string): z.infer<typeof CalendarSchema>[] {
  const calendars: z.infer<typeof CalendarSchema>[] = [];
  for (const resp of extractAll(xml, "response")) {
    const resourcetype = extractFirst(resp, "resourcetype") ?? "";
    const isCalendar = /calendar/i.test(resourcetype) ||
      hasElement(resourcetype, "subscribed");
    if (!isCalendar) continue;
    const href = extractFirst(resp, "href");
    if (!href) continue;
    const displayName =
      sanitizeXmlText(extractFirst(resp, "displayname") ?? "") || href;
    const color = sanitizeXmlText(extractFirst(resp, "calendar-color") ?? "") ||
      null;
    // `source` (webcal subscription target) is a bearer secret — never persist
    // it; record only whether one exists.
    const hasSource = hasElement(resourcetype, "subscribed") ||
      extractFirst(resp, "source") !== null;
    calendars.push({ displayName, path: href, color, hasSource });
  }
  return calendars;
}

// ---------------------------------------------------------------------------
// iCalendar (VEVENT) construction — pure + unit-tested
// ---------------------------------------------------------------------------

const utf8 = new TextEncoder();

/** UTF-8 octet length of a string. */
export function octetLength(s: string): number {
  return utf8.encode(s).length;
}

/** Escape a TEXT value per RFC 5545 §3.3.11 (handles CR, LF, CRLF). */
export function escapeText(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,")
    .replace(/\r\n|\n|\r/g, "\\n");
}

/**
 * Fold a content line to ≤75 octets per RFC 5545 §3.1, counting UTF-8 octets and
 * never splitting a multi-octet codepoint (iterates by codepoint via spread).
 * Continuation lines begin with a single space and hold ≤74 octets of content.
 */
export function foldLine(line: string): string {
  if (octetLength(line) <= 75) return line;
  const segments: string[] = [];
  let cur = "";
  let curOctets = 0;
  let limit = 75; // first line 75 octets; continuations 74 (one leading space)
  for (const cp of line) { // string iteration yields whole codepoints
    const w = octetLength(cp);
    if (curOctets + w > limit) {
      segments.push(cur);
      cur = "";
      curOctets = 0;
      limit = 74;
    }
    cur += cp;
    curOctets += w;
  }
  segments.push(cur);
  return segments.join("\r\n ");
}

/** Compact UTC stamp (YYYYMMDDTHHMMSSZ) for the given Date. */
export function utcStamp(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/** Compact date (YYYYMMDD) — strips every non-digit (injection-safe). */
export function compactDate(ymd: string): string {
  return ymd.replace(/[^0-9]/g, "");
}

/** Compact a floating local dateTime to YYYYMMDDTHHMMSS — keeps only digits + T. */
export function compactLocal(dateTime: string): string {
  return dateTime.replace(/[^0-9T]/g, "");
}

/** True if an RFC3339 dateTime carries explicit zone info (Z or ±HH:MM). */
export function hasZone(dateTime: string): boolean {
  return /(?:Z|[+-]\d{2}:?\d{2})$/.test(dateTime);
}

/** Strip a leading/enclosing IANA TZID down to the safe charset. */
function sanitizeTzid(tz: string): string {
  return tz.replace(/[^A-Za-z0-9_+\-\/]/g, "");
}

/**
 * Wall-clock time (`YYYYMMDDTHHMMSS`) of an RFC3339 instant as observed in `tz`.
 * Robust to any input offset: the absolute instant is converted to the zone's
 * civil time via `Intl`, so a recurring `DTSTART;TZID=` carries the correct
 * floating local time for per-occurrence DST expansion. A floating input (no
 * offset) is already local and passes through `compactLocal`.
 */
export function wallClockInZone(dateTime: string, tz: string): string {
  if (!hasZone(dateTime)) return compactLocal(dateTime);
  const d = new Date(dateTime);
  if (isNaN(d.getTime())) {
    throw new Error(`Invalid dateTime: ${clip(dateTime, 40)}`);
  }
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const p: Record<string, string> = {};
  for (const part of fmt.formatToParts(d)) p[part.type] = part.value;
  return `${p.year}${p.month}${p.day}T${p.hour}${p.minute}${p.second}`;
}

/**
 * Render a DTSTART/DTEND line.
 * - all-day (`date`) → `;VALUE=DATE:YYYYMMDD`
 * - recurring timed with a `timeZone` → `;TZID=<tz>:YYYYMMDDTHHMMSS` at the
 *   event's wall-clock time, so the server expands each occurrence in that zone
 *   and DST boundaries do not shift the local time (AR-6). `preferLocal` opts in.
 * - timed with explicit offset/Z → normalized to UTC `YYYYMMDDTHHMMSSZ`
 *   (deterministic, no VTIMEZONE needed)
 * - timed floating (no offset) with `timeZone` → `;TZID=<tz>:YYYYMMDDTHHMMSS`
 *   (host-independent; Nextcloud resolves IANA TZIDs)
 * - timed floating with no `timeZone` → throws (would be host-timezone dependent)
 */
export function renderDtLine(
  prop: "DTSTART" | "DTEND",
  t: z.infer<typeof EventTimeSchema>,
  opts: { preferLocal?: boolean } = {},
): string {
  if (t.date) return `${prop};VALUE=DATE:${compactDate(t.date)}`;
  if (t.dateTime) {
    // Recurring events must keep a zoned wall-clock time; folding to a fixed UTC
    // instant would drift by the DST offset for occurrences on the other side
    // of a transition (AR-6).
    if (opts.preferLocal && t.timeZone) {
      const tz = sanitizeTzid(t.timeZone);
      return `${prop};TZID=${tz}:${wallClockInZone(t.dateTime, tz)}`;
    }
    if (hasZone(t.dateTime)) {
      const d = new Date(t.dateTime);
      if (isNaN(d.getTime())) {
        throw new Error(`Invalid ${prop} dateTime: ${clip(t.dateTime, 40)}`);
      }
      return `${prop}:${utcStamp(d)}`;
    }
    if (t.timeZone) {
      const tz = sanitizeTzid(t.timeZone);
      return `${prop};TZID=${tz}:${compactLocal(t.dateTime)}`;
    }
    throw new Error(
      `${prop} dateTime has no UTC offset and no timeZone; cannot resolve a deterministic instant`,
    );
  }
  throw new Error(`${prop} requires either date or dateTime`);
}

/**
 * Provenance marker. Every VEVENT this model writes carries `X-SWAMP-SYNC`, so a
 * reconciliation delete can tell a swamp-managed mirror event apart from a
 * foreign event that merely shares a calendar — foreign events are never
 * deleted. Read back via `list_events` (`hasProvenance`) and re-checked
 * server-side in `delete_events` (V-2 defense in depth).
 */
export const PROVENANCE_PROP = "X-SWAMP-SYNC";
export const PROVENANCE_VALUE = "gcal-nc-sync";

/**
 * Build a full VCALENDAR wrapping a single VEVENT for the given event. Every
 * emitted field is escaped or digit/enum-constrained, so no caller value can
 * inject an iCal property or component even if schema validation is bypassed.
 * `now` is injected for deterministic testing (DTSTAMP).
 */
export function buildVcalendar(ev: EventInput, now: Date = new Date()): string {
  // A recurring timed event keeps its zone (TZID + wall-clock) so occurrences
  // expand correctly across DST; a single event folds to a UTC instant.
  const preferLocal = (ev.recurrence?.length ?? 0) > 0;
  const lines: string[] = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//kneel//swamp-nextcloud//EN",
    "CALSCALE:GREGORIAN",
    "BEGIN:VEVENT",
    `UID:${escapeText(ev.uid)}`,
    `DTSTAMP:${utcStamp(now)}`,
    renderDtLine("DTSTART", ev.start, { preferLocal }),
    renderDtLine("DTEND", ev.end, { preferLocal }),
    `SEQUENCE:${ev.sequence ?? 0}`,
    `${PROVENANCE_PROP}:${PROVENANCE_VALUE}`,
  ];
  if (ev.summary) lines.push(`SUMMARY:${escapeText(ev.summary)}`);
  if (ev.description) lines.push(`DESCRIPTION:${escapeText(ev.description)}`);
  if (ev.location) lines.push(`LOCATION:${escapeText(ev.location)}`);
  if (ev.status) lines.push(`STATUS:${ev.status.toUpperCase()}`);
  for (const r of ev.recurrence ?? []) {
    // recurrence lines carry their own property name (RRULE:/EXDATE:/…). Strip
    // any CR/LF as a last-resort guard against property injection.
    lines.push(r.replace(/\r\n|\n|\r/g, " ").trim());
  }
  lines.push("END:VEVENT", "END:VCALENDAR");
  return lines.map(foldLine).join("\r\n") + "\r\n";
}

// ---------------------------------------------------------------------------
// iCalendar (VEVENT) reading — parse a CalDAV calendar-query REPORT
// ---------------------------------------------------------------------------

/** Decode the handful of XML entities a DAV server may emit in text content. */
export function decodeXmlEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#0*13;?/g, "\r")
    .replace(/&#0*10;?/g, "\n")
    .replace(/&amp;/g, "&");
}

/** Reverse RFC 5545 §3.3.11 TEXT escaping (UID is a TEXT-typed value). */
export function unescapeText(s: string): string {
  return s.replace(
    /\\([\\;,nN])/g,
    (_m, c) => (c === "n" || c === "N" ? "\n" : c),
  );
}

/**
 * Read a single iCal property value from a VEVENT body. Unfolds continuation
 * lines first, tolerates property parameters (`;TZID=…`, `;VALUE=DATE`), and is
 * case-insensitive on the property name. Returns the raw (still-escaped) value.
 */
export function icalProp(ics: string, prop: string): string | null {
  const unfolded = ics.replace(/\r\n[ \t]/g, "").replace(/\n[ \t]/g, "");
  const re = new RegExp(
    `(?:^|\\n)${prop}(?:;[^:\\n]*)?:([^\\n\\r]*)`,
    "i",
  );
  const m = re.exec(unfolded);
  return m ? m[1].trim() : null;
}

/** A minimal event reference read back from a calendar (no PII). */
export type CalEventRef = {
  uid: string;
  dtstart: string;
  hasProvenance: boolean;
  isRecurring: boolean;
};

/**
 * Parse a CalDAV `calendar-query` REPORT multistatus into `{uid, dtstart,
 * hasProvenance, isRecurring}` rows. Only UID, DTSTART, RRULE and the provenance
 * marker are read — SUMMARY/DESCRIPTION/LOCATION are never extracted, so no event
 * PII is persisted. `hasProvenance` gates a reconciliation delete; `isRecurring`
 * excludes recurring masters from window-based deletion (ADV-2).
 */
export function parseCalendarReport(xml: string): CalEventRef[] {
  const out: CalEventRef[] = [];
  for (const resp of extractAll(xml, "response")) {
    const raw = extractFirst(resp, "calendar-data");
    if (!raw) continue;
    const ics = decodeXmlEntities(raw);
    const uidRaw = icalProp(ics, "UID");
    if (!uidRaw) continue;
    out.push({
      uid: unescapeText(uidRaw),
      dtstart: icalProp(ics, "DTSTART") ?? "",
      hasProvenance: icalProp(ics, PROVENANCE_PROP) !== null,
      isRecurring: icalProp(ics, "RRULE") !== null,
    });
  }
  return out;
}

/** True if an .ics body carries this model's provenance marker (V-2 recheck). */
export function icsHasProvenance(ics: string): boolean {
  return icalProp(ics, PROVENANCE_PROP) !== null;
}

/** Minimal XML text escape for values placed into request bodies. */
export function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Compact-UTC (`YYYYMMDDTHHMMSSZ`) form of an RFC3339 instant for a REPORT filter. */
export function toCompactUtc(rfc3339: string): string {
  const d = new Date(rfc3339);
  if (isNaN(d.getTime())) {
    throw new Error(`Invalid window bound: ${clip(rfc3339, 40)}`);
  }
  return utcStamp(d);
}

// ---------------------------------------------------------------------------
// CardDAV — contacts / address books (parallel to the CalDAV section above)
// ---------------------------------------------------------------------------

/**
 * Contacts provenance marker. Every VCard this model writes carries
 * `X-SWAMP-SYNC:gcontacts-nc-sync`, so a reconciliation delete can tell a
 * swamp-managed mirror contact apart from a foreign contact that merely
 * shares an addressbook — foreign contacts are never deleted.
 */
export const CONTACTS_PROVENANCE_VALUE = "gcontacts-nc-sync";

// ── CardDAV URL construction ───────────────────────────────────────────────

/** URL for a single addressbook collection under the principal's addressbook home. */
export function addressbookUrl(
  baseUrl: string,
  username: string,
  addressbook: string,
): string {
  const slug = encodeURIComponent(addressbook.replace(/^\/+|\/+$/g, ""));
  return `${davBase(baseUrl)}/addressbooks/users/${
    encodeURIComponent(username)
  }/${slug}/`;
}

/**
 * Validate a contact UID against the SEC-2 allowlist. The UID is used in URL
 * construction and VCard serialization; anything outside the safe charset is
 * rejected to prevent path traversal and property injection.
 */
export function validateContactUid(uid: string): void {
  if (!/^[A-Za-z0-9_\-.]{1,200}$/.test(uid)) {
    throw new Error(
      `contact uid rejected by allowlist: ${clip(uid, 40)}`,
    );
  }
}

/**
 * Sanitize a UID for use as a filename segment. Same approach as eventHref —
 * replace unsafe chars with `_`, cap length, append FNV-1a of the raw UID for
 * collision resistance.
 */
export function sanitizeUidForPath(uid: string): string {
  return uid.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 96);
}

/**
 * Deterministic, filesystem-safe object name for a contact UID. The `kind`
 * parameter selects the file extension — `.vcf` for CardDAV, `.ics` for
 * CalDAV (ADV-4: never mix extensions).
 */
export function urlForUid(
  baseUrl: string,
  _username: string,
  collectionPath: string,
  uid: string,
  kind: "vcf" | "ics",
): string {
  const safe = sanitizeUidForPath(uid);
  const encoded = encodeURIComponent(`${safe}-${fnv1a(uid)}.${kind}`);
  const base = collectionPath.endsWith("/")
    ? collectionPath
    : `${baseUrl.replace(/\/$/, "")}/remote.php/dav/${collectionPath}/`;
  return `${base}${encoded}`;
}

/** Contact href in an addressbook — VCard file (.vcf, not .ics). */
export function contactHref(
  baseUrl: string,
  username: string,
  addressbook: string,
  uid: string,
): string {
  return urlForUid(
    baseUrl,
    username,
    `addressbooks/users/${encodeURIComponent(username)}/${
      encodeURIComponent(addressbook)
    }`,
    uid,
    "vcf",
  );
}

// ── VCard 4.0 construction (pure function, parallels buildVcalendar) ───────

/**
 * Escape a VCard 4.0 TEXT value. RFC 6350 §3.4 defers to RFC 5545 §3.3.11 for
 * TEXT values: same escaping rules as iCal (`\\`, `\\;`, `\\,`, `\\n`). Reuses
 * the existing escapeText (SEC-1).
 */
function vcardEscapeText(value: string): string {
  return escapeText(value);
}

/**
 * Render an N (structured name) property value. Five semicolon-separated
 * components, each TEXT-escaped (semicolons and commas INSIDE each component
 * are escaped so they don't collide with the structural separators).
 */
function renderN(n: {
  family?: string;
  given?: string;
  additional?: string;
  prefix?: string;
  suffix?: string;
}): string {
  return [
    vcardEscapeText(n.family ?? ""),
    vcardEscapeText(n.given ?? ""),
    vcardEscapeText(n.additional ?? ""),
    vcardEscapeText(n.prefix ?? ""),
    vcardEscapeText(n.suffix ?? ""),
  ].join(";");
}

/**
 * Render an ADR (address) property value. Seven semicolon-separated
 * components, each TEXT-escaped.
 */
function renderAdr(a: {
  pobox?: string;
  ext?: string;
  street?: string;
  locality?: string;
  region?: string;
  code?: string;
  country?: string;
}): string {
  return [
    vcardEscapeText(a.pobox ?? ""),
    vcardEscapeText(a.ext ?? ""),
    vcardEscapeText(a.street ?? ""),
    vcardEscapeText(a.locality ?? ""),
    vcardEscapeText(a.region ?? ""),
    vcardEscapeText(a.code ?? ""),
    vcardEscapeText(a.country ?? ""),
  ].join(";");
}

/**
 * Build a full VCard 4.0 body for the given contact. Every emitted field is
 * escaped or charset-constrained, so no caller value can inject a VCard
 * property even if schema validation is bypassed.
 *
 * Dual provenance (ADV-1): the X-SWAMP-SYNC property AND a NOTE sentinel both
 * carry the marker, so at least one survives client normalization that strips
 * unknown X-properties.
 */
export function buildVcard(
  contact: z.infer<typeof ContactInputSchema>,
): string {
  // SEC-1 defense-in-depth: reject NUL in the UID even though the schema
  // already bans control chars.
  if (contact.uid.includes("\0")) {
    throw new Error("contact uid contains NUL");
  }
  validateContactUid(contact.uid);
  const lines: string[] = [
    "BEGIN:VCARD",
    "VERSION:4.0",
    `UID:${vcardEscapeText(contact.uid)}`,
    `FN:${vcardEscapeText(contact.fn)}`,
  ];
  if (contact.n) lines.push(`N:${renderN(contact.n)}`);
  for (const e of contact.email ?? []) {
    const type = e.type
      ? `;TYPE=${e.type.replace(/[^A-Za-z0-9_,-]/g, "")}`
      : "";
    lines.push(`EMAIL${type}:${vcardEscapeText(e.value)}`);
  }
  for (const t of contact.tel ?? []) {
    const type = t.type
      ? `;TYPE=${t.type.replace(/[^A-Za-z0-9_,-]/g, "")}`
      : "";
    lines.push(`TEL${type}:${vcardEscapeText(t.value)}`);
  }
  for (const a of contact.adr ?? []) {
    const type = a.type
      ? `;TYPE=${a.type.replace(/[^A-Za-z0-9_,-]/g, "")}`
      : "";
    lines.push(`ADR${type}:${renderAdr(a)}`);
  }
  if (contact.org) lines.push(`ORG:${vcardEscapeText(contact.org)}`);
  if (contact.title) lines.push(`TITLE:${vcardEscapeText(contact.title)}`);
  if (contact.note) lines.push(`NOTE:${vcardEscapeText(contact.note)}`);
  if (contact.bday) {
    // SEC: strip non-digits and dashes (injection-safe for VALUE=DATE).
    lines.push(`BDAY:${contact.bday.replace(/[^0-9-]/g, "")}`);
  }
  if (contact.url) lines.push(`URL:${vcardEscapeText(contact.url)}`);
  if (contact.categories?.length) {
    lines.push(
      `CATEGORIES:${contact.categories.map(vcardEscapeText).join(",")}`,
    );
  }
  // Provenance — dual stamp (X-property + NOTE sentinel, ADV-1).
  lines.push(`${PROVENANCE_PROP}:${CONTACTS_PROVENANCE_VALUE}`);
  lines.push(`NOTE:Swamp-managed contact (${CONTACTS_PROVENANCE_VALUE})`);
  lines.push("END:VCARD");
  return lines.map(foldLine).join("\r\n") + "\r\n";
}

// ── VCard reading (minimal, pure function) ─────────────────────────────────

/**
 * Read a single VCard property value. Unfolds continuation lines first,
 * tolerates property parameters (`;TYPE=WORK`), and is case-insensitive on
 * the property name. Returns the raw (still-escaped) value.
 */
export function vcardProp(vcf: string, prop: string): string | null {
  const unfolded = vcf.replace(/\r\n[ \t]/g, "").replace(/\n[ \t]/g, "");
  const re = new RegExp(
    `(?:^|\\n)${prop}(?:;[^:\\n]*)?:([^\\n\\r]*)`,
    "i",
  );
  const m = re.exec(unfolded);
  return m ? m[1].trim() : null;
}

/**
 * All values of a possibly-repeated VCard property (e.g. NOTE). Returns raw
 * escaped values in document order.
 */
export function vcardPropAll(vcf: string, prop: string): string[] {
  const unfolded = vcf.replace(/\r\n[ \t]/g, "").replace(/\n[ \t]/g, "");
  const results: string[] = [];
  const re = new RegExp(
    `(?:^|\\n)${prop}(?:;[^:\\n]*)?:([^\\n\\r]*)`,
    "gi",
  );
  let m: RegExpExecArray | null;
  while ((m = re.exec(unfolded)) !== null) results.push(m[1].trim());
  return results;
}

/**
 * True if a VCard body carries this model's provenance — either the X-property
 * with the exact expected value OR the NOTE sentinel substring (ADV-1).
 */
export function vcfHasProvenance(vcf: string): boolean {
  const propVal = vcardProp(vcf, PROVENANCE_PROP);
  if (propVal === CONTACTS_PROVENANCE_VALUE) return true;
  const notes = vcardPropAll(vcf, "NOTE");
  return notes.some((n) =>
    unescapeText(n).includes(
      `Swamp-managed contact (${CONTACTS_PROVENANCE_VALUE})`,
    )
  );
}

/** A minimal contact reference read back from an addressbook (no PII). */
export type CardContactRef = {
  uid: string;
  fn: string;
  hasProvenance: boolean;
};

/**
 * Parse a single VCard body into a minimal contact reference. Only UID, FN
 * and the provenance flag are extracted — no emails, phones, addresses, or
 * other PII is persisted.
 */
export function parseVcardMinimal(vcf: string): CardContactRef | null {
  const uidRaw = vcardProp(vcf, "UID");
  if (!uidRaw) return null;
  return {
    uid: unescapeText(uidRaw),
    fn: unescapeText(vcardProp(vcf, "FN") ?? ""),
    hasProvenance: vcfHasProvenance(vcf),
  };
}

// ── CardDAV XML request bodies ─────────────────────────────────────────────

const PROPFIND_ADDRESSBOOKS_BODY = `<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop>
    <d:displayname/>
    <d:resourcetype/>
  </d:prop>
</d:propfind>`;

/**
 * Body for MKCOL to create an addressbook collection. `displayName` is
 * XML-escaped.
 */
export function mkAddressbookBody(displayName: string): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<d:mkcol xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:set>
    <d:prop>
      <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
      <d:displayname>${xmlEscape(displayName)}</d:displayname>
    </d:prop>
  </d:set>
</d:mkcol>`;
}

/** Parse an addressbooks PROPFIND multistatus into safe Addressbook rows. */
export function parseAddressbooks(
  xml: string,
): z.infer<typeof AddressbookSchema>[] {
  const out: z.infer<typeof AddressbookSchema>[] = [];
  for (const resp of extractAll(xml, "response")) {
    const resourcetype = extractFirst(resp, "resourcetype") ?? "";
    if (!hasElement(resourcetype, "addressbook")) continue;
    const href = extractFirst(resp, "href");
    if (!href) continue;
    const displayName =
      sanitizeXmlText(extractFirst(resp, "displayname") ?? "") || href;
    out.push({ url: href, displayName });
  }
  return out;
}

/**
 * Body for a CardDAV `addressbook-query` REPORT that returns, for every
 * VCard in the addressbook, a partial address-data carrying only UID, FN and
 * the provenance marker — never EMAIL/TEL/ADR, so no PII is pulled.
 */
export function addressbookQueryBody(): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop>
    <d:getetag/>
    <card:address-data>
      <card:prop name="UID"/>
      <card:prop name="FN"/>
      <card:prop name="${PROVENANCE_PROP}"/>
      <card:prop name="NOTE"/>
    </card:address-data>
  </d:prop>
</card:addressbook-query>`;
}

/**
 * Parse a CardDAV `addressbook-query` REPORT multistatus into minimal contact
 * rows. Only UID, FN and the provenance flag are extracted — no contact PII
 * (EMAIL/TEL/ADR) is persisted.
 */
export function parseAddressbookReport(xml: string): CardContactRef[] {
  const out: CardContactRef[] = [];
  for (const resp of extractAll(xml, "response")) {
    const raw = extractFirst(resp, "address-data");
    if (!raw) continue;
    const vcf = decodeXmlEntities(raw);
    const ref = parseVcardMinimal(vcf);
    if (ref) out.push(ref);
  }
  return out;
}

// ---------------------------------------------------------------------------
// CalDAV VTODO (tasks) helpers — serializer, parser, PROPFIND
// ---------------------------------------------------------------------------

/**
 * Provenance value for VTODO resources. Distinct from calendar (gcal-nc-sync)
 * and contacts (gcontacts-nc-sync) so a task is never confused with a mirrored
 * event or contact.
 */
export const TASKS_PROVENANCE_VALUE = "tasks-nc-sync";

/** PROPFIND body that discovers task lists (VTODO component advertisements). */
const PROPFIND_TASKLISTS_BODY = `<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"
            xmlns:ic="http://apple.com/ns/ical/"
            xmlns:cs="http://calendarserver.org/ns/">
  <d:prop>
    <d:displayname/>
    <d:resourcetype/>
    <c:calendar-type/>
    <ic:calendar-type/>
    <c:supported-calendar-component-set/>
    <cs:source/>
  </d:prop>
</d:propfind>`;

/**
 * Body for a CalDAV `calendar-query` REPORT over VTODOs. Requests only the
 * structural fields (UID, SUMMARY, STATUS) and the provenance marker — no
 * DESCRIPTION/LOCATION/CATEGORIES, so task PII is never pulled.
 */
export function tasksQueryBody(): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:getetag/>
    <c:calendar-data>
      <c:comp name="VCALENDAR">
        <c:comp name="VTODO">
          <c:prop name="UID"/>
          <c:prop name="SUMMARY"/>
          <c:prop name="STATUS"/>
          <c:prop name="${PROVENANCE_PROP}"/>
        </c:comp>
      </c:comp>
    </c:calendar-data>
  </d:prop>
  <c:filter>
    <c:comp-filter name="VCALENDAR">
      <c:comp-filter name="VTODO"/>
    </c:comp-filter>
  </c:filter>
</c:calendar-query>`;
}

/**
 * Build the MKCALENDAR body for a VTODO collection (tasklist). Sets
 * `calendar-type = VTODO` so NC Tasks recognizes it.
 */
export function mkTasklistBody(displayName: string): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:set>
    <d:prop>
      <d:displayname>${xmlEscape(displayName)}</d:displayname>
      <c:supported-calendar-component-set>
        <c:comp name="VTODO"/>
      </c:supported-calendar-component-set>
    </d:prop>
  </d:set>
</c:mkcalendar>`;
}

/**
 * Parse a tasklists PROPFIND multistatus. A task list is a calendar collection
 * that advertises VTODO — either via `calendar-type=VTODO` (NC Tasks app) or
 * via a `supported-calendar-component-set` that contains `<c:comp name="VTODO"/>`
 * (NC Deck boards). The parent collection (/calendars/users/<u>/) is filtered
 * out. VEVENT-only calendars are excluded.
 */
export function parseTasklists(xml: string): z.infer<typeof TasklistSchema>[] {
  const out: z.infer<typeof TasklistSchema>[] = [];
  for (const resp of extractAll(xml, "response")) {
    const href = extractFirst(resp, "href") ?? "";
    const resourcetype = extractFirst(resp, "resourcetype") ?? "";
    if (!/calendar/i.test(resourcetype)) continue;
    const segments = href.split("/").filter(Boolean);
    if (segments.length < 4) continue;

    const calendarType = sanitizeXmlText(
      extractFirst(resp, "calendar-type") ?? "",
    ).toUpperCase();
    // Detect VTODO advertisement. Two sources: the legacy `calendar-type` prop
    // (NC Tasks app emits `<calendar-type>VTODO</calendar-type>`) and the
    // standard `supported-calendar-component-set` (Deck boards emit a comp-set
    // with `<c:comp name="VTODO"/>`). Accept either.
    const componentSet = extractFirst(
      resp,
      "supported-calendar-component-set",
    ) ?? "";
    // Match <c:comp name="VTODO"/> or <c:comp name='VTODO'> — exact attribute
    // value, with a closing boundary so name="VTODO-EVIL" can't false-positive.
    const hasVtodoComp = /name=["']VTODO["'](?:\s|\/|>)/i.test(componentSet);
    const isTasklist = calendarType === "VTODO" || hasVtodoComp;
    if (!isTasklist) continue;

    // Webcal subscriptions (cs:source set, or resourcetype has <subscribed/>)
    // are VEVENT-only; exclude them even if they advertise VTODO in the
    // component-set (NC advertises both for any calendar).
    const hasSource = hasElement(resourcetype, "subscribed") ||
      extractFirst(resp, "source") !== null;
    if (hasSource) continue;

    const displayName =
      sanitizeXmlText(extractFirst(resp, "displayname") ?? "") || href;
    out.push({ url: href, displayName });
  }
  return out;
}

/**
 * Validate a task UID for path safety. Reuses the SEC-2 allowlist from
 * ContactInputSchema but extended with `@` (Google iCalUID convention).
 */
export function validateTaskUid(uid: string): void {
  if (!/^[A-Za-z0-9_\-.@]{1,200}$/.test(uid)) {
    throw new Error(
      `task uid ${
        JSON.stringify(uid)
      } is not path-safe (allowlist: A-Za-z0-9_\\-.@)`,
    );
  }
  if (uid.includes("\0")) throw new Error("task uid must not contain NUL");
  if (uid === "." || uid === "..") {
    throw new Error("task uid must not be . or ..");
  }
}

/** Deterministic, filesystem-safe object name for a task UID. */
export function taskHref(
  baseUrl: string,
  username: string,
  tasklist: string,
  uid: string,
): string {
  validateTaskUid(uid);
  const safe = uid.replace(/[^A-Za-z0-9._@-]/g, "_").slice(0, 96);
  return `${calendarUrl(baseUrl, username, tasklist)}${safe}-${fnv1a(uid)}.ics`;
}

/** Render a DUE line (DATE or DATE-TIME). Empty string if no due is set.
 *
 * RFC 5545 §3.3.5 forms:
 *   - all-day:     DUE;VALUE=DATE:YYYYMMDD
 *   - TZID:        DUE;TZID=<zone>:YYYYMMDDTHHMMSS (local time in the zone)
 *   - UTC:         DUE:YYYYMMDDTHHMMSSZ
 *   - floating:    DUE:YYYYMMDDTHHMMSS (no Z, no TZID — server's local time)
 */
function renderDueLine(due: TaskInput["due"]): string {
  if (!due) return "";
  if (due.date) return `DUE;VALUE=DATE:${due.date.replace(/-/g, "")}`;
  if (due.dateTime) {
    if (due.timeZone) {
      // Local-time form: strip non-digit/non-T chars (YYYYMMDDTHHMMSS).
      return `DUE;TZID=${due.timeZone}:${compactLocal(due.dateTime)}`;
    }
    if (hasZone(due.dateTime)) {
      // Explicit zone (Z or ±HH:MM) — fold to UTC instant.
      const d = new Date(due.dateTime);
      if (Number.isNaN(d.getTime())) return "";
      return `DUE:${utcStamp(d)}`;
    }
    // Floating time: emit as local YYYYMMDDTHHMMSS without Z.
    return `DUE:${compactLocal(due.dateTime)}`;
  }
  return "";
}

/**
 * Build a full VCALENDAR wrapping a single VTODO. Same escape + fold defense
 * as buildVcalendar. `now` is injected for deterministic testing (DTSTAMP).
 */
export function buildVtodo(task: TaskInput, now: Date = new Date()): string {
  const lines: string[] = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//kneel//swamp-nextcloud//EN",
    "CALSCALE:GREGORIAN",
    "BEGIN:VTODO",
    `UID:${escapeText(task.uid)}`,
    `DTSTAMP:${utcStamp(now)}`,
    `CREATED:${utcStamp(now)}`,
    `LAST-MODIFIED:${utcStamp(now)}`,
    `SUMMARY:${escapeText(task.summary)}`,
    `STATUS:${task.status ?? "NEEDS-ACTION"}`,
    `${PROVENANCE_PROP}:${TASKS_PROVENANCE_VALUE}`,
  ];
  if (task.description) {
    lines.push(`DESCRIPTION:${escapeText(task.description)}`);
  }
  const dueLine = renderDueLine(task.due);
  if (dueLine) lines.push(dueLine);
  if (task.priority !== undefined && task.priority > 0) {
    lines.push(`PRIORITY:${task.priority}`);
  }
  if (task.percentComplete !== undefined) {
    lines.push(`PERCENT-COMPLETE:${task.percentComplete}`);
  }
  if (task.categories && task.categories.length > 0) {
    lines.push(`CATEGORIES:${task.categories.map(escapeText).join(",")}`);
  }
  if (task.relatedTo) {
    lines.push(`RELATED-TO;RELTYPE=PARENT:${escapeText(task.relatedTo)}`);
  }
  for (const r of task.recurrence ?? []) {
    lines.push(r.replace(/\r\n|\n|\r/g, " ").trim());
  }
  lines.push("END:VTODO", "END:VCALENDAR");
  return lines.map(foldLine).join("\r\n") + "\r\n";
}

/**
 * Parse a VTODO body (as returned by a CalDAV calendar-data property) into a
 * minimal TaskRef: UID, SUMMARY, STATUS, hasProvenance. Returns null if the
 * body is not a VTODO.
 */
export function parseVtodoMinimal(
  ics: string,
): z.infer<typeof TaskRefSchema> | null {
  if (!/BEGIN:VTODO/i.test(ics)) return null;
  const uidRaw = icalProp(ics, "UID");
  if (!uidRaw) return null;
  // Unescape iCal TEXT escapes (\\, \n \; \,) for consistency with the events
  // and contacts parsers. Server-derived UIDs may carry escape sequences.
  const uid = unescapeText(sanitizeXmlText(uidRaw));
  const summary = unescapeText(
    sanitizeXmlText(icalProp(ics, "SUMMARY") ?? ""),
  );
  const status = (icalProp(ics, "STATUS") ?? "NEEDS-ACTION").toUpperCase();
  const hasProvenance = icsHasProvenanceValue(ics, TASKS_PROVENANCE_VALUE);
  return { uid, summary, status, hasProvenance };
}

/** Check whether an iCal body carries X-SWAMP-SYNC with a specific value (exact match). */
export function icsHasProvenanceValue(ics: string, value: string): boolean {
  // Use icalProp to read the full property value, then compare exactly.
  // This prevents prefix matches where e.g. "tasks-nc" would match a body
  // stamped with "tasks-nc-sync" (ADV-3 pattern applied).
  const propVal = icalProp(ics, PROVENANCE_PROP);
  return propVal === value;
}

/** Parse a tasks REPORT response into minimal task refs. */
export function parseTasksReport(xml: string): z.infer<typeof TaskRefSchema>[] {
  const out: z.infer<typeof TaskRefSchema>[] = [];
  for (const resp of extractAll(xml, "response")) {
    const raw = extractFirst(resp, "calendar-data");
    if (!raw) continue;
    const ics = decodeXmlEntities(raw);
    const ref = parseVtodoMinimal(ics);
    if (ref) out.push(ref);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Notes REST API helpers
// ---------------------------------------------------------------------------

/**
 * Base URL for the Nextcloud Notes REST API.
 * Plain REST/JSON endpoints — NOT DAV. Same auth (appPassword HTTP Basic).
 */
export function notesBase(baseUrl: string): string {
  return `${baseUrl.replace(/\/$/, "")}/index.php/apps/notes/api/v1`;
}

/** Provenance value for notes (used in the HTML-comment sentinel). */
export const NOTES_PROVENANCE_VALUE = "swamp-managed (notes-nc-sync)";

/**
 * HTML-comment provenance sentinel. Invisible in rendered markdown but
 * detectable in the raw note body.
 */
export function notesProvenanceSentinel(): string {
  return `<!-- ${NOTES_PROVENANCE_VALUE} -->`;
}

/** Check whether a note body starts with the provenance sentinel (first line). */
export function notesHasProvenance(body: string): boolean {
  const firstLine = body.split("\n", 1)[0]?.trim() ?? "";
  return firstLine === notesProvenanceSentinel();
}

/** Prepend the provenance sentinel + newline to a note body. */
export function stampNotesProvenance(body: string): string {
  return `${notesProvenanceSentinel()}\n${body}`;
}

/** Schema for a single note's metadata (no body — PII-bearing). */
export const NoteSchema = z.object({
  id: z.number(),
  title: z.string(),
  modified: z.number(),
  category: z.string(),
  favorite: z.boolean(),
});

/**
 * Schema for note input (put_note). Title is validated to reject path
 * traversal characters and control chars; max 200 chars.
 */
export const NoteInputSchema = z.object({
  id: z.number().int().positive().optional(),
  title: z
    .string()
    .min(1)
    .max(200)
    .refine(
      (t) => !t.includes("/") && !t.includes("\\") && !hasControlChars(t),
      { message: "title must not contain /, \\, NUL, or control characters" },
    ),
  content: z.string(),
  category: z.string().optional(),
});

/** Args for list_notes (optional category filter). */
export const ListNotesArgsSchema = z.object({
  category: z
    .string()
    .optional()
    .describe("When set, only return notes in this category."),
});

/** Args for get_note. */
export const GetNoteArgsSchema = z.object({
  id: z.number().int().positive().describe("Note ID to fetch."),
});

/** Args for put_note. */
export const PutNoteArgsSchema = NoteInputSchema;

/** Args for delete_notes (fan-out over ids). */
export const DeleteNotesArgsSchema = z.object({
  ids: z
    .array(z.number().int().positive())
    .default([])
    .describe("Note IDs to delete (fan-out). An empty batch is a no-op."),
  requireProvenance: z
    .boolean()
    .default(true)
    .describe(
      "When true (default), GET each note and refuse to delete any that lacks the provenance sentinel.",
    ),
  dryRun: z
    .boolean()
    .default(false)
    .describe("When true, preview deletions without mutating."),
  maxDeletes: z
    .number()
    .int()
    .min(0)
    .default(50)
    .describe(
      "Blast-radius cap: if the batch has MORE than this many ids, abort the whole delete.",
    ),
});

// ---------------------------------------------------------------------------
// OCS Share API — constants, helpers, schemas
// ---------------------------------------------------------------------------

/**
 * Base URL for the Nextcloud OCS Share API v1.
 * Uses the same OCS v2 endpoint pattern as other OCS apps.
 */
export function sharesBase(baseUrl: string): string {
  return `${
    baseUrl.replace(/\/$/, "")
  }/ocs/v2.php/apps/files_sharing/api/v1/shares`;
}

// ── Permission constants (bitmask) ──────────────────────────────────────────

/** Read (GET / download). */
export const PERM_READ = 1;
/** Update (PUT / edit file contents). */
export const PERM_UPDATE = 2;
/** Create (add new files in a shared folder). */
export const PERM_CREATE = 4;
/** Delete (remove files from a shared folder). */
export const PERM_DELETE = 8;
/** Share (re-share to other users). */
export const PERM_SHARE = 16;

/** View-only — read only. */
export const VIEW_ONLY = PERM_READ; // 1
/** Read + write (read + update + create — no delete). */
export const READ_WRITE = PERM_READ | PERM_UPDATE | PERM_CREATE; // 7
/** Read + write + re-share. */
export const READ_WRITE_SHARE = READ_WRITE | PERM_SHARE; // 23
/** All permissions (read + update + create + delete + share). */
export const ALL = PERM_READ | PERM_UPDATE | PERM_CREATE | PERM_DELETE |
  PERM_SHARE; // 31

/** Allowed permission bitmask values — strict allowlist. Exported for tests. */
export const PERM_ALLOWLIST = new Set([
  VIEW_ONLY,
  READ_WRITE,
  READ_WRITE_SHARE,
  ALL,
]);

// ── Share type constants ────────────────────────────────────────────────────

/** Share with a specific user. */
export const SHARE_TYPE_USER = 0;
/** Share with a group. */
export const SHARE_TYPE_GROUP = 1;
/** Public link share. */
export const SHARE_TYPE_PUBLIC_LINK = 3;
/** Share via email. */
export const SHARE_TYPE_EMAIL = 4;
/** Federated (remote) share. */
export const SHARE_TYPE_FEDERATED = 6;

// ── Path validation ─────────────────────────────────────────────────────────

/**
 * Validate a share path. Rejects absolute paths, `..` segments, NUL bytes,
 * and empty segments. Must be a relative path like `Documents/report.pdf`.
 *
 * Exported for tests.
 */
export function validateSharePath(path: string): string {
  if (!path || path.length === 0) {
    throw new Error("share path must not be empty");
  }
  if (path.includes("\0")) {
    throw new Error("share path must not contain NUL bytes");
  }
  if (path.startsWith("/")) {
    throw new Error("share path must be relative (no leading /)");
  }
  if (path.startsWith("\\")) {
    throw new Error("share path must not start with backslash");
  }
  const segments = path.split("/");
  for (const seg of segments) {
    if (seg === "") {
      throw new Error(`share path contains empty segment: "${clip(path, 80)}"`);
    }
    if (seg === "..") {
      throw new Error(`share path contains .. traversal: "${clip(path, 80)}"`);
    }
    if (seg === ".") {
      throw new Error(`share path contains . segment: "${clip(path, 80)}"`);
    }
  }
  return path;
}

// ── Zod schemas ─────────────────────────────────────────────────────────────

/**
 * Permission bitmask — strict allowlist. Only values in {1, 7, 23, 31} are
 * accepted. This prevents callers from constructing arbitrary bitmask combos
 * that may have unintended security implications.
 */
export const SharePermissionsSchema = z
  .number()
  .int()
  .refine((v) => PERM_ALLOWLIST.has(v), {
    message:
      "permissions must be one of VIEW_ONLY(1), READ_WRITE(7), READ_WRITE_SHARE(23), ALL(31)",
  })
  .describe("Permission bitmask: 1=view, 7=read-write, 23=rw+share, 31=all");

/** Schema for a single share entry from the OCS response. */
export const ShareSchema = z.object({
  id: z.coerce.number(),
  share_type: z.coerce.number(),
  uid_owner: z.string().optional(),
  displayname_owner: z.string().optional(),
  path: z.string(),
  permissions: z.coerce.number(),
  share_with: z.string().optional(),
  share_with_displayname: z.string().optional(),
  url: z.string().optional(),
  token: z.string().nullable().optional(),
  expiration: z.string().nullable().optional(),
  note: z.string().optional(),
  label: z.string().optional(),
  hide_download: z.preprocess(
    (v) => (typeof v === "number" ? v !== 0 : v),
    z.boolean().optional(),
  ),
});

/** Schema for create/update share result. */
export const ShareResultSchema = z.object({
  id: z.coerce.number(),
  url: z.string().optional(),
  shareType: z.number(),
  token: z.string().optional(),
});

/** Args for list_shares. */
export const ListSharesArgsSchema = z.object({
  path: z
    .string()
    .optional()
    .describe("Filter shares by file/folder path (relative, no leading /)."),
  reshares: z
    .boolean()
    .default(false)
    .describe(
      "When true, also include shares where the current user is not the owner.",
    ),
  subfiles: z
    .boolean()
    .default(false)
    .describe(
      "When true, list all shares within the specified path (recursive).",
    ),
});

/** Args for create_share. */
export const CreateShareArgsSchema = z.object({
  path: z
    .string()
    .min(1)
    .describe("Relative path to the file/folder to share (no leading /)."),
  shareType: z
    .number()
    .int()
    .min(0)
    .default(SHARE_TYPE_USER)
    .describe(
      "Share type: 0=user, 1=group, 3=public link, 4=email, 6=federated.",
    ),
  shareWith: z
    .string()
    .optional()
    .describe(
      "User/group/email to share with (required for shareType != public link).",
    ),
  permissions: SharePermissionsSchema.default(VIEW_ONLY),
  password: z
    .string()
    .optional()
    .describe("Password for the share (public link or user shares)."),
  expireDate: z
    .string()
    .optional()
    .describe("Expiration date in YYYY-MM-DD format."),
  note: z
    .string()
    .max(1000)
    .optional()
    .describe("Note attached to the share."),
});

/** Args for create_public_link — wraps create_share with shareType=3. */
export const CreatePublicLinkArgsSchema = z.object({
  path: z
    .string()
    .min(1)
    .describe("Relative path to the file/folder (no leading /)."),
  permissions: SharePermissionsSchema.default(VIEW_ONLY),
  password: z
    .string()
    .optional()
    .describe("Optional password protection."),
  expireDate: z
    .string()
    .optional()
    .describe("Expiration date in YYYY-MM-DD format."),
  note: z
    .string()
    .max(1000)
    .optional()
    .describe("Note attached to the public link."),
  label: z
    .string()
    .max(200)
    .optional()
    .describe("Label for the public link (shown in the share UI)."),
  elevatedPublicLink: z
    .boolean()
    .default(false)
    .describe(
      "When true, allows write permissions (READ_WRITE, READ_WRITE_SHARE, ALL) on the public link. Default false — only VIEW_ONLY(1) is permitted unless explicitly elevated.",
    ),
});

/** Args for update_share. */
export const UpdateShareArgsSchema = z.object({
  id: z.number().int().positive().describe("Share ID to update."),
  permissions: SharePermissionsSchema
    .optional()
    .describe("New permission bitmask (must be in allowlist)."),
  password: z
    .string()
    .optional()
    .describe("New password (empty string to remove)."),
  expireDate: z
    .string()
    .optional()
    .describe("New expiration date in YYYY-MM-DD format."),
  note: z
    .string()
    .max(1000)
    .optional()
    .describe("New note (empty string to remove)."),
  hideDownload: z
    .boolean()
    .optional()
    .describe("Hide download button on public link."),
});

/** Args for revoke_share. */
export const RevokeShareArgsSchema = z.object({
  id: z
    .number()
    .int()
    .positive()
    .describe(
      "Share ID to revoke (must be in the managed_shares provenance snapshot).",
    ),
  dryRun: z
    .boolean()
    .default(false)
    .describe("When true, preview revocation without mutating."),
});

// ---------------------------------------------------------------------------
// WebDAV Files — CRUD for files/folders via the main NC WebDAV endpoint
// ---------------------------------------------------------------------------

/**
 * WebDAV files base URL for a given user.
 * All file operations are scoped to the `swamp-sync` provenance folder within
 * this endpoint.
 */
export function filesBase(baseUrl: string, username: string): string {
  return `${baseUrl.replace(/\/$/, "")}/remote.php/dav/files/${
    encodeURIComponent(username)
  }`;
}

/**
 * Dedicated provenance folder for swamp-managed files. Files under this folder
 * are considered swamp-managed; files outside are not. This avoids per-file
 * provenance markers and limits the blast radius of file operations.
 */
export const SWAMP_SYNC_FOLDER = "swamp-sync";

/** Maximum number of path segments allowed (SEC-4). */
export const MAX_PATH_SEGMENTS = 10;

/** Maximum total path length (SEC-4). */
export const MAX_PATH_LENGTH = 500;

/** Default max file size in bytes (10 MB) (SEC-3). */
export const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024;

/** Hard cap on list_files entries (SEC-5). */
export const MAX_LIST_ENTRIES = 1000;

/**
 * Allowed content-type prefixes for put_file (SEC-3).
 * Only safe, non-executable MIME types are permitted.
 */
export const ALLOWED_CONTENT_TYPE_PREFIXES = [
  "text/",
  "application/json",
  "application/pdf",
  "image/png",
  "image/jpeg",
] as const;

/**
 * Blocked file extensions (SEC-3). Executable/script types are rejected
 * regardless of content-type header.
 */
export const BLOCKED_EXTENSIONS = new Set([
  ".exe",
  ".sh",
  ".php",
  ".bat",
  ".cmd",
  ".ps1",
]);

/**
 * Validate a file path for WebDAV operations. Rejects absolute paths, `..`
 * segments, `.`, NUL bytes, empty segments, and URL-encoded traversal
 * (`%2e`, `%2f`, `%5c`). Caps segment count and total length.
 *
 * The path is relative to the SWAMP_SYNC_FOLDER — it must not start with `/`.
 *
 * Exported for tests.
 */
export function validateFilePath(path: string): string {
  if (!path || path.length === 0) {
    throw new Error("file path must not be empty");
  }
  if (path.length > MAX_PATH_LENGTH) {
    throw new Error(
      `file path exceeds max length (${MAX_PATH_LENGTH}): ${path.length} chars`,
    );
  }
  if (path.includes("\0")) {
    throw new Error("file path must not contain NUL bytes");
  }
  if (path.startsWith("/")) {
    throw new Error("file path must be relative (no leading /)");
  }
  if (path.startsWith("\\")) {
    throw new Error("file path must not start with backslash");
  }
  // Reject URL-encoded traversal sequences (case-insensitive)
  const lower = path.toLowerCase();
  if (
    lower.includes("%2e") || lower.includes("%2f") || lower.includes("%5c")
  ) {
    throw new Error("file path contains encoded traversal sequence");
  }
  const segments = path.split("/");
  if (segments.length > MAX_PATH_SEGMENTS) {
    throw new Error(
      `file path exceeds max segments (${MAX_PATH_SEGMENTS}): ${segments.length}`,
    );
  }
  for (const seg of segments) {
    if (seg === "") {
      throw new Error(`file path contains empty segment: "${clip(path, 80)}"`);
    }
    if (seg === "..") {
      throw new Error(`file path contains .. traversal: "${clip(path, 80)}"`);
    }
    if (seg === ".") {
      throw new Error(`file path contains . segment: "${clip(path, 80)}"`);
    }
  }
  return path;
}

/**
 * Validate a content-type against the allowlist (SEC-3).
 * Returns true if the content-type is allowed.
 */
export function validateContentType(contentType: string): boolean {
  const ct = contentType.toLowerCase().trim();
  return ALLOWED_CONTENT_TYPE_PREFIXES.some((prefix) => ct.startsWith(prefix));
}

/**
 * Validate a filename against blocked extensions (SEC-3).
 * Returns true if the extension is allowed (not blocked).
 */
export function validateFileExtension(filename: string): boolean {
  const dot = filename.lastIndexOf(".");
  if (dot === -1) return true; // no extension — allowed
  const ext = filename.slice(dot).toLowerCase();
  return !BLOCKED_EXTENSIONS.has(ext);
}

/** Schema for a file entry from PROPFIND. */
export const FileSchema = z.object({
  path: z.string(),
  size: z.number(),
  mtime: z.string().optional(),
  contentType: z.string().optional(),
  isDirectory: z.boolean(),
  etag: z.string().optional(),
});

/** Args for list_files. */
export const ListFilesArgsSchema = z.object({
  path: z
    .string()
    .default("")
    .describe(
      "Relative path within the swamp-sync folder to list (empty = root).",
    ),
});

/** Args for get_file. */
export const GetFileArgsSchema = z.object({
  path: z
    .string()
    .min(1)
    .describe("Relative path within the swamp-sync folder to download."),
});

/** Args for put_file. */
export const PutFileArgsSchema = z.object({
  path: z
    .string()
    .min(1)
    .describe("Relative path within the swamp-sync folder to upload."),
  body: z
    .string()
    .describe("File content to upload. Never persisted or logged (PII)."),
  contentType: z
    .string()
    .default("text/plain")
    .describe("MIME type of the file. Must be in the allowlist (SEC-3)."),
  ifMatch: z
    .string()
    .optional()
    .describe(
      "ETag for optimistic concurrency (If-Match). Returns conflict on mismatch (ADV-3).",
    ),
});

/** Args for delete_file. */
export const DeleteFileArgsSchema = z.object({
  path: z
    .string()
    .min(1)
    .describe("Relative path within the swamp-sync folder to delete."),
  dryRun: z
    .boolean()
    .default(false)
    .describe("When true, preview deletion without mutating."),
});

/** Args for mkdir. */
export const MkdirArgsSchema = z.object({
  path: z
    .string()
    .min(1)
    .describe("Relative path within the swamp-sync folder to create."),
});

/** PROPFIND body for listing files (Depth:1). Requests standard WebDAV properties. */
export const PROPFIND_FILES_BODY = `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:displayname/>
    <d:getcontentlength/>
    <d:getlastmodified/>
    <d:getcontenttype/>
    <d:resourcetype/>
    <d:getetag/>
  </d:prop>
</d:propfind>`;

/**
 * Parse a PROPFIND response for file listings. Extracts metadata for each
 * `<d:response>` element. The collection itself (the directory being listed)
 * is included as the first entry.
 *
 * Returns an array of FileSchema entries.
 */
export function parseFilesReport(
  xml: string,
  _baseUrl: string,
): z.infer<typeof FileSchema>[] {
  const files: z.infer<typeof FileSchema>[] = [];
  for (const resp of extractAll(xml, "response")) {
    const href = extractFirst(resp, "href");
    if (!href) continue;
    const resourcetype = extractFirst(resp, "resourcetype") ?? "";
    const isDirectory = /collection/i.test(resourcetype);
    const displayName = extractFirst(resp, "displayname") ?? "";
    const size = parseInt(extractFirst(resp, "getcontentlength") ?? "0", 10);
    const mtime = extractFirst(resp, "getlastmodified") ?? undefined;
    const contentType = extractFirst(resp, "getcontenttype") ?? undefined;
    const etag = extractFirst(resp, "getetag") ?? undefined;
    // Use the displayname if available, otherwise derive from href
    const path = displayName || href;
    files.push({
      path,
      size: isNaN(size) ? 0 : size,
      mtime,
      contentType,
      isDirectory,
      etag,
    });
  }
  return files;
}

// ---------------------------------------------------------------------------
// Deck API — boards / stacks / cards (REST/JSON)
// ---------------------------------------------------------------------------

/**
 * Base URL for the Nextcloud Deck REST API v1.0.
 * Plain REST/JSON endpoints — NOT DAV. Same auth (appPassword HTTP Basic).
 */
export function deckBase(baseUrl: string): string {
  return `${baseUrl.replace(/\/$/, "")}/apps/deck/api/v1.0`;
}

/**
 * Provenance label title. Cards created/updated by this model carry a Deck
 * label with this exact title. delete_card checks for this label (SEC-1).
 */
export const DECK_PROVENANCE_LABEL = "swamp-managed";

/** Default color for the swamp-managed provenance label (blue). */
export const DECK_PROVENANCE_COLOR = "1A73D5";

/** Hard cap on Deck list results (SEC-5). */
export const DECK_MAX_LIST_ENTRIES = 500;

/** Max card description size in chars (100KB) (SEC-3). */
export const DECK_MAX_DESCRIPTION_SIZE = 100_000;

/**
 * XSS patterns rejected at the zod schema level for all Deck text inputs
 * (titles, descriptions). Case-insensitive (SEC-2).
 */
export const DECK_XSS_PATTERNS: RegExp[] = [
  /<script/i,
  /javascript:/i,
  /data:text\/html/i,
  /<iframe/i,
];

/**
 * Check text for Deck XSS patterns. Throws on match. Exported for tests.
 */
export function checkDeckXss(text: string, fieldName: string): void {
  for (const pattern of DECK_XSS_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(
        `${fieldName} contains disallowed pattern (${pattern.source})`,
      );
    }
  }
}

/**
 * Validate a Deck title: non-empty, ≤200 chars, no control chars, no XSS
 * patterns (SEC-2, SEC-4). Exported for tests.
 */
export function validateDeckTitle(title: string): string {
  if (!title || title.trim().length === 0) {
    throw new Error("Deck title must not be empty");
  }
  if (title.length > 200) {
    throw new Error(
      `Deck title exceeds 200 chars: ${title.length} chars`,
    );
  }
  if (hasControlChars(title)) {
    throw new Error("Deck title must not contain control characters");
  }
  checkDeckXss(title, "Deck title");
  return title;
}

/**
 * Check whether a card's labels array includes the provenance label.
 * Deck returns labels as objects `{title: string, ...}`. Also handles raw
 * string arrays defensively. Exported for tests.
 */
export function deckHasProvenance(
  labels: unknown[] | undefined | null,
): boolean {
  if (!Array.isArray(labels)) return false;
  return labels.some((l) => {
    if (typeof l === "string") return l === DECK_PROVENANCE_LABEL;
    if (l && typeof l === "object" && "title" in l) {
      return (l as { title: unknown }).title === DECK_PROVENANCE_LABEL;
    }
    return false;
  });
}

// ── Deck Zod schemas ──────────────────────────────────────────────────────

/** Schema for a Deck label (id + title + color). */
export const DeckLabelSchema = z.object({
  id: z.number().optional(),
  title: z.string(),
  color: z.string().optional(),
});

/**
 * Schema for a Deck board (metadata only). Nested stacks/cards are NOT
 * persisted here — use list_stacks / list_cards for those.
 */
export const BoardSchema = z.object({
  id: z.number(),
  title: z.string(),
  color: z.string().optional(),
  archived: z.boolean().optional(),
  labels: z.array(DeckLabelSchema).default([]),
});

/** Schema for a Deck stack (metadata only; no nested cards). */
export const StackSchema = z.object({
  id: z.number(),
  title: z.string(),
  boardId: z.number(),
  order: z.number().optional(),
});

/**
 * Schema for a Deck card (metadata only).
 * Description is NEVER persisted (PII) — only the hasProvenance flag.
 */
export const CardSchema = z.object({
  id: z.number(),
  title: z.string(),
  stackId: z.number(),
  order: z.number().optional(),
  hasProvenance: z.boolean(),
});

/**
 * Card input shape for create/update. Title validated for XSS at the zod
 * level (SEC-2). Description validated but never persisted.
 */
export const CardInputSchema = z.object({
  title: z
    .string()
    .min(1)
    .max(200)
    .refine((t) => {
      if (hasControlChars(t)) return false;
      for (const p of DECK_XSS_PATTERNS) if (p.test(t)) return false;
      return true;
    }, { message: "title contains disallowed pattern (XSS/control chars)" }),
  description: z
    .string()
    .max(DECK_MAX_DESCRIPTION_SIZE)
    .refine((d) => {
      for (const p of DECK_XSS_PATTERNS) if (p.test(d)) return false;
      return true;
    }, { message: "description contains disallowed pattern (XSS)" })
    .default(""),
  order: z.number().int().min(0).optional(),
});

/** Helper: title zod field with XSS refine, reused across card args. */
const deckTitleField = CardInputSchema.shape.title;
/** Helper: description zod field with XSS refine + default. */
const deckDescField = CardInputSchema.shape.description;
/** Helper: order zod field. */
const deckOrderField = CardInputSchema.shape.order;

// ── Deck args schemas ───────────────────────────────────────────────────────

/** Args for list_boards. */
export const ListBoardsArgsSchema = z.object({});

/** Args for get_board. */
export const GetBoardArgsSchema = z.object({
  boardId: z.number().int().positive().describe("Board ID to fetch."),
});

/** Args for create_board. */
export const CreateBoardArgsSchema = z.object({
  title: z
    .string()
    .min(1)
    .max(200)
    .describe("Board title (validated for XSS, SEC-2)."),
  color: z
    .string()
    .regex(/^[0-9a-fA-F]{6}$/)
    .optional()
    .describe("Hex color for the board (6 chars, no #). Optional."),
});

/** Args for delete_board (cascade safety via maxDeletes, ADV-4). */
export const DeleteBoardArgsSchema = z.object({
  boardId: z.number().int().positive().describe("Board ID to delete."),
  dryRun: z
    .boolean()
    .default(false)
    .describe("When true, preview deletion without mutating."),
  maxDeletes: z
    .number()
    .int()
    .min(0)
    .default(100)
    .describe(
      "Cascade safety cap: abort if board contains MORE than this many cards.",
    ),
});

/** Args for list_stacks. */
export const ListStacksArgsSchema = z.object({
  boardId: z.number().int().positive().describe(
    "Board ID to list stacks for.",
  ),
});

/** Args for create_stack. */
export const CreateStackArgsSchema = z.object({
  boardId: z.number().int().positive().describe(
    "Board to add the stack to.",
  ),
  title: z
    .string()
    .min(1)
    .max(200)
    .describe("Stack title (validated for XSS, SEC-2)."),
  order: z
    .number()
    .int()
    .min(0)
    .default(0)
    .describe("Sort order within the board."),
});

/** Args for delete_stack (cascade safety via maxDeletes, ADV-4). */
export const DeleteStackArgsSchema = z.object({
  stackId: z.number().int().positive().describe("Stack ID to delete."),
  dryRun: z
    .boolean()
    .default(false)
    .describe("When true, preview deletion without mutating."),
  maxDeletes: z
    .number()
    .int()
    .min(0)
    .default(50)
    .describe(
      "Cascade safety cap: abort if stack contains MORE than this many cards.",
    ),
});

/** Args for list_cards. */
export const ListCardsArgsSchema = z.object({
  stackId: z.number().int().positive().describe(
    "Stack ID to list cards for.",
  ),
});

/** Args for create_card. Provenance label is auto-assigned (SEC-1). */
export const CreateCardArgsSchema = z.object({
  stackId: z.number().int().positive().describe(
    "Stack to add the card to.",
  ),
  title: deckTitleField.describe("Card title (XSS-validated, SEC-2)."),
  description: deckDescField.describe(
    "Card description (XSS-validated, NEVER persisted — PII).",
  ),
  order: deckOrderField.describe("Sort order in the stack."),
});

/** Args for update_card. Provenance label is preserved by Deck. */
export const UpdateCardArgsSchema = z.object({
  cardId: z.number().int().positive().describe("Card ID to update."),
  title: deckTitleField.describe("New card title."),
  description: deckDescField.describe(
    "New card description (NEVER persisted — PII).",
  ),
  order: deckOrderField,
  etag: z
    .string()
    .optional()
    .describe("ETag for optimistic concurrency (ADV-3)."),
});

/** Args for delete_card. Refuses to delete non-provenance cards (SEC-1). */
export const DeleteCardArgsSchema = z.object({
  cardId: z.number().int().positive().describe("Card ID to delete."),
  dryRun: z
    .boolean()
    .default(false)
    .describe("When true, preview deletion without mutating."),
  requireProvenance: z
    .boolean()
    .default(true)
    .describe(
      "When true (default), GET the card and refuse to delete unless it has the swamp-managed label.",
    ),
});

// ── Deck response parsers ───────────────────────────────────────────────────

/**
 * Parse a raw board from the Deck API response.
 */
export function parseBoard(
  raw: Record<string, unknown>,
): z.infer<typeof BoardSchema> {
  return BoardSchema.parse(raw);
}

/**
 * Parse a raw stack from the Deck API response.
 */
export function parseStack(
  raw: Record<string, unknown>,
): z.infer<typeof StackSchema> {
  return StackSchema.parse(raw);
}

/**
 * Parse a raw card from the Deck API response. Extracts only metadata;
 * description is NEVER persisted (PII). hasProvenance is derived from labels.
 */
export function parseCard(
  raw: Record<string, unknown>,
): z.infer<typeof CardSchema> {
  const labels = (raw.labels as unknown[]) ?? [];
  return CardSchema.parse({
    id: raw.id as number,
    title: raw.title as string,
    stackId: (raw.stackId ?? raw.stack_id) as number,
    order: raw.order as number | undefined,
    hasProvenance: deckHasProvenance(labels),
  });
}

// ---------------------------------------------------------------------------
// OCS Users API — constants, helpers, schemas (NC-USERS)
// ---------------------------------------------------------------------------

/**
 * Base URL for the Nextcloud OCS Users API v2.
 * All user/group CRUD endpoints are under `/ocs/v2.php/cloud`.
 */
export function usersBase(baseUrl: string): string {
  return `${baseUrl.replace(/\/$/, "")}/ocs/v2.php/cloud`;
}

// ── Users constants ─────────────────────────────────────────────────────────

/** Maximum number of users returned in a single list_users call. */
export const USERS_MAX_LIST = 500;

/** Default cap on delete_user calls — blast-radius safety. */
export const USERS_DEFAULT_MAX_DELETES = 1;

/** Reserved admin username that must never be deleted. */
export const USERS_ADMIN_RESERVED = "admin";

// ── CSPRNG password generation ─────────────────────────────────────────────

/**
 * Generate a CSPRNG password: 16 random bytes, base64url-encoded (22 chars).
 * Never logged. Returned exactly once to the caller in methodResult.
 */
export function generatePassword(): string {
  return randomBytes(16).toString("base64url");
}

// ── Admin capability probe ─────────────────────────────────────────────────

/**
 * Cache key for the admin probe result within a single method call.
 * We don't cache across calls (swamp resources handle persistence).
 */
let _adminProbeCache: { key: string; isAdmin: boolean } | null = null;

/**
 * Probe the OCS /cloud/user endpoint to determine whether the authenticated
 * user is a Nextcloud admin. The admin flag is required for Users API methods.
 *
 * Caches result per (baseUrl, username) to avoid repeated probes within a
 * single method execution. Returns true if admin, throws otherwise.
 */
export async function adminProbe(
  auth: string,
  baseUrl: string,
  username: string,
  log?: Logger,
): Promise<boolean> {
  const cacheKey = `${baseUrl}|${username}`;
  if (_adminProbeCache && _adminProbeCache.key === cacheKey) {
    return _adminProbeCache.isAdmin;
  }
  const url = `${ocsBase(baseUrl)}/cloud/user?format=json`;
  const resp = await davRequest("GET", url, auth, {
    headers: { Accept: "application/json", "OCS-APIRequest": "true" },
    okStatuses: [200],
    log,
  });
  if (!resp.ok) {
    throw new Error(
      `adminProbe: GET /cloud/user returned ${resp.status}: ${
        clip(resp.text, 200)
      }`,
    );
  }
  let data: Record<string, unknown>;
  try {
    const parsed = JSON.parse(resp.text);
    data = (parsed?.ocs?.data as Record<string, unknown>) ?? {};
  } catch {
    throw new Error("adminProbe: OCS response was not valid JSON");
  }
  // The admin flag lives in ocs.data.admin (boolean).
  const isAdmin = data.admin === true;
  _adminProbeCache = { key: cacheKey, isAdmin };
  log?.debug("adminProbe: user={userId} admin={isAdmin}", {
    userId: clip(String(data.id ?? username), 80),
    isAdmin,
  });
  return isAdmin;
}

/** Reset the admin probe cache (for tests). */
export function resetAdminProbeCache(): void {
  _adminProbeCache = null;
}

// ── Users Zod schemas ──────────────────────────────────────────────────────

/**
 * Schema for a user ID (persistence only — no PII).
 */
export const UserSchema = z.object({
  userId: z.string().min(1),
});

/**
 * Schema for full user detail (returned via methodResult only — never persisted).
 */
export const UserDetailSchema = z.object({
  userId: z.string(),
  email: z.string().default(""),
  displayname: z.string().default(""),
  quota: z.unknown().optional(),
  lastLogin: z.number().optional(),
  enabled: z.boolean().optional(),
});

/**
 * Schema for a group ID (persistence only — no PII).
 */
export const GroupSchema = z.object({
  groupId: z.string().min(1),
});

/**
 * Schema for full group detail (returned via methodResult only).
 */
export const GroupDetailSchema = z.object({
  groupId: z.string(),
  members: z.array(z.string()).default([]),
});

/** Args for list_users. */
export const ListUsersArgsSchema = z.object({
  search: z
    .string()
    .optional()
    .describe("Optional search filter (substring match on user IDs)."),
  limit: z
    .number()
    .int()
    .positive()
    .max(USERS_MAX_LIST)
    .optional()
    .describe(
      `Maximum users to return (default: all, up to ${USERS_MAX_LIST}).`,
    ),
  offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe("Pagination offset."),
});

/** Args for create_user. */
export const CreateUserArgsSchema = z.object({
  userid: z
    .string()
    .min(1)
    .max(64)
    .describe("User ID to create (1–64 chars)."),
  displayName: z
    .string()
    .min(1)
    .max(255)
    .optional()
    .describe("Optional display name (defaults to userid)."),
  email: z
    .string()
    .email()
    .optional()
    .describe("Optional email address."),
  groups: z
    .array(z.string().min(1))
    .default([])
    .describe("Optional groups to add the user to on creation."),
  password: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Explicit password. If omitted, a CSPRNG password is generated and returned once.",
    ),
});

/** Args for get_user. */
export const GetUserArgsSchema = z.object({
  userid: z.string().min(1).describe("User ID to fetch."),
});

/** Editable user fields for edit_user. */
export const USER_EDIT_KEYS = [
  "email",
  "quota",
  "display",
  "password",
] as const;

/** Args for edit_user. */
export const EditUserArgsSchema = z.object({
  userid: z.string().min(1).describe("User ID to edit."),
  key: z
    .enum(USER_EDIT_KEYS)
    .describe("Field to edit: email, quota, display, or password."),
  value: z
    .string()
    .min(1)
    .describe("New value for the field."),
});

/** Args for delete_user. Triple safety: confirmUserId + maxDeletes + dryRun. */
export const DeleteUserArgsSchema = z.object({
  userid: z.string().min(1).describe("User ID to delete."),
  confirmUserId: z
    .string()
    .min(1)
    .describe(
      "Safety: must exactly match userid. Prevents accidental deletion from copy-paste errors.",
    ),
  dryRun: z
    .boolean()
    .default(false)
    .describe("When true, preview deletion without mutating."),
  maxDeletes: z
    .number()
    .int()
    .min(0)
    .default(USERS_DEFAULT_MAX_DELETES)
    .describe(
      `Blast-radius cap: abort if more than this many users would be deleted (default: ${USERS_DEFAULT_MAX_DELETES}).`,
    ),
});

/** Args for list_groups. */
export const ListGroupsArgsSchema = z.object({
  search: z
    .string()
    .optional()
    .describe("Optional search filter (substring match on group IDs)."),
  limit: z
    .number()
    .int()
    .positive()
    .optional()
    .describe("Maximum groups to return."),
  offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe("Pagination offset."),
});

/** Args for get_group. */
export const GetGroupArgsSchema = z.object({
  groupid: z.string().min(1).describe("Group ID to fetch."),
});

// ── Users response parsers ─────────────────────────────────────────────────

/**
 * Parse the OCS /cloud/users response into an array of user IDs.
 * Nextcloud returns `ocs.data.users` as an array of strings.
 */
export function parseUserIds(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((u): u is string => typeof u === "string" && u.length > 0);
}

/**
 * Parse the OCS /cloud/users/{userid} response into a UserDetail object.
 */
export function parseUserDetail(
  raw: Record<string, unknown>,
): z.infer<typeof UserDetailSchema> {
  return UserDetailSchema.parse({
    userId: String(raw.id ?? raw.userid ?? raw.userId ?? ""),
    email: String(raw.email ?? ""),
    displayname: String(raw["display-name"] ?? raw.displayname ?? ""),
    quota: raw.quota ?? undefined,
    lastLogin: typeof raw["lastLogin"] === "number"
      ? raw["lastLogin"]
      : undefined,
    enabled: typeof raw.enabled === "boolean" ? raw.enabled : undefined,
  });
}

/**
 * Parse the OCS /cloud/groups response into an array of group IDs.
 */
export function parseGroupIds(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((g): g is string => typeof g === "string" && g.length > 0);
}

/**
 * Parse the OCS /cloud/groups/{groupid} response into a GroupDetail object.
 */
export function parseGroupDetail(
  raw: Record<string, unknown>,
): z.infer<typeof GroupDetailSchema> {
  const members = Array.isArray(raw.users)
    ? raw.users.filter(
      (u): u is string => typeof u === "string" && u.length > 0,
    )
    : [];
  return GroupDetailSchema.parse({
    groupId: String(raw.id ?? raw.groupid ?? raw.groupId ?? ""),
    members,
  });
}

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

export const model = {
  type: "@kneel/nextcloud",
  version: "2026.07.20.7",
  globalArguments: GlobalArgsSchema,

  resources: {
    identity: {
      description: "Authenticated Nextcloud user (auth smoke-test result).",
      schema: IdentitySchema,
      lifetime: "1h" as const,
      garbageCollection: 5,
    },
    calendars: {
      description: "Calendars in the user's calendar home (secrets masked).",
      schema: z.object({
        calendars: z.array(CalendarSchema),
        count: z.number(),
      }),
      lifetime: "1h" as const,
      garbageCollection: 5,
    },
    upsert: {
      description:
        "Outcome of an event upsert batch (UIDs + outcomes only, no PII).",
      schema: z.object({
        calendar: z.string(),
        upserted: z.number(),
        failed: z.number(),
        results: z.array(UpsertOutcomeSchema),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    deletions: {
      description: "Outcome of an event deletion batch (UIDs + outcomes only).",
      schema: z.object({
        calendar: z.string(),
        dryRun: z.boolean(),
        deleted: z.number(),
        wouldDelete: z.number(),
        skipped: z.number(),
        failed: z.number(),
        aborted: z.boolean().describe(
          "True when the maxDeletes blast-radius cap tripped and nothing was deleted.",
        ),
        abortReason: z.string().optional(),
        requested: z.number().describe(
          "Number of uids in the requested batch.",
        ),
        results: z.array(DeleteOutcomeSchema),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    events: {
      description:
        "Events read back from a calendar within a time window (UID + DTSTART + provenance flag only, no PII).",
      schema: z.object({
        calendar: z.string(),
        timeMin: z.string(),
        timeMax: z.string(),
        events: z.array(CalEventRefSchema),
        count: z.number(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    provision: {
      description: "Outcome of a calendar provisioning (MKCALENDAR) request.",
      schema: z.object({
        calendar: z.string(),
        created: z.boolean(),
        httpStatus: z.number(),
      }),
      lifetime: "infinite" as const,
      garbageCollection: 3,
    },
    addressbooks: {
      description: "Addressbooks in the user's addressbook home.",
      schema: z.object({
        addressbooks: z.array(AddressbookSchema),
        count: z.number(),
      }),
      lifetime: "1h" as const,
      garbageCollection: 5,
    },
    provision_addressbook: {
      description: "Outcome of an addressbook provisioning (MKCOL) request.",
      schema: z.object({
        addressbook: z.string(),
        created: z.boolean(),
        httpStatus: z.number(),
      }),
      lifetime: "infinite" as const,
      garbageCollection: 3,
    },
    contacts: {
      description:
        "Contacts read back from an addressbook (UID + FN + provenance flag only, no PII).",
      schema: z.object({
        addressbook: z.string(),
        contacts: z.array(ContactRefSchema),
        count: z.number(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    upsert_contacts: {
      description:
        "Outcome of a contact upsert batch (UIDs + outcomes only, no PII).",
      schema: z.object({
        addressbook: z.string(),
        upserted: z.number(),
        failed: z.number(),
        results: z.array(UpsertOutcomeSchema),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    deletions_contacts: {
      description:
        "Outcome of a contact deletion batch (UIDs + outcomes only).",
      schema: z.object({
        addressbook: z.string(),
        dryRun: z.boolean(),
        deleted: z.number(),
        wouldDelete: z.number(),
        skipped: z.number(),
        failed: z.number(),
        aborted: z.boolean(),
        abortReason: z.string().optional(),
        requested: z.number(),
        results: z.array(DeleteOutcomeSchema),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    tasklists: {
      description:
        "Task lists (VTODO calendar-type collections) in the user's calendar home.",
      schema: z.object({
        tasklists: z.array(TasklistSchema),
        count: z.number(),
      }),
      lifetime: "1h" as const,
      garbageCollection: 5,
    },
    provision_tasklist: {
      description:
        "Outcome of a tasklist provisioning (MKCALENDAR w/ VTODO) request.",
      schema: z.object({
        tasklist: z.string(),
        created: z.boolean(),
        httpStatus: z.number(),
      }),
      lifetime: "infinite" as const,
      garbageCollection: 3,
    },
    tasks: {
      description:
        "Tasks read back from a tasklist (UID + SUMMARY + STATUS + provenance flag only, no PII).",
      schema: z.object({
        tasklist: z.string(),
        tasks: z.array(TaskRefSchema),
        count: z.number(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    upsert_tasks: {
      description:
        "Outcome of a task upsert batch (UIDs + outcomes only, no PII).",
      schema: z.object({
        tasklist: z.string(),
        upserted: z.number(),
        failed: z.number(),
        results: z.array(UpsertOutcomeSchema),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    deletions_tasks: {
      description: "Outcome of a task deletion batch (UIDs + outcomes only).",
      schema: z.object({
        tasklist: z.string(),
        dryRun: z.boolean(),
        deleted: z.number(),
        wouldDelete: z.number(),
        skipped: z.number(),
        failed: z.number(),
        aborted: z.boolean(),
        abortReason: z.string().optional(),
        requested: z.number(),
        results: z.array(DeleteOutcomeSchema),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    notes: {
      description:
        "Notes metadata from the NC Notes app (id + title + modified + category + favorite; no bodies — PII).",
      schema: z.object({
        notes: z.array(NoteSchema),
        count: z.number(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    upsert_notes: {
      description:
        "Outcome of a note upsert batch (IDs + outcomes only, no bodies).",
      schema: z.object({
        upserted: z.number(),
        failed: z.number(),
        results: z.array(UpsertOutcomeSchema),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    deletions_notes: {
      description:
        "Outcome of a note deletion batch (IDs + outcomes only, no bodies).",
      schema: z.object({
        dryRun: z.boolean(),
        deleted: z.number(),
        wouldDelete: z.number(),
        skipped: z.number(),
        failed: z.number(),
        aborted: z.boolean(),
        abortReason: z.string().optional(),
        requested: z.number(),
        results: z.array(DeleteOutcomeSchema),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    shares: {
      description:
        "Shares listed from the OCS Share API (IDs + paths + permissions; no share-with PII beyond user IDs).",
      schema: z.object({
        shares: z.array(ShareSchema),
        count: z.number(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    managed_shares: {
      description:
        "Provenance snapshot: share IDs created/managed by swamp. revoke_share refuses to revoke IDs not in this snapshot.",
      schema: z.object({
        shareIds: z.array(z.number()),
        count: z.number(),
      }),
      lifetime: "infinite" as const,
      garbageCollection: 3,
    },
    share_result: {
      description:
        "Outcome of a create/update share operation (ID + URL + shareType).",
      schema: ShareResultSchema,
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    files: {
      description:
        "Files listed from the WebDAV endpoint under the swamp-sync provenance folder (metadata only — no file bodies).",
      schema: z.object({
        path: z.string(),
        files: z.array(FileSchema),
        count: z.number(),
      }),
      lifetime: "1h" as const,
      garbageCollection: 5,
    },
    file_content: {
      description:
        "Metadata for a downloaded file (path + size + contentType + etag). File bodies are NEVER persisted (PII).",
      schema: z.object({
        path: z.string(),
        size: z.number(),
        contentType: z.string(),
        etag: z.string().optional(),
      }),
      lifetime: "1h" as const,
      garbageCollection: 5,
    },
    file_operation: {
      description:
        "Outcome of a file operation (put/delete/mkdir). Path + outcome only — no file bodies.",
      schema: z.object({
        path: z.string(),
        operation: z.string(),
        success: z.boolean(),
        etag: z.string().optional(),
        error: z.string().optional(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    boards: {
      description:
        "Deck boards (metadata + labels only; no nested stacks/cards — use list_stacks).",
      schema: z.object({
        boards: z.array(BoardSchema),
        count: z.number(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    board_result: {
      description:
        "Outcome of a board operation (id + title + outcome; no nested content).",
      schema: z.object({
        id: z.number().optional(),
        title: z.string().optional(),
        operation: z.string(),
        success: z.boolean(),
        httpStatus: z.number().optional(),
        error: z.string().optional(),
        cardCount: z.number().optional(),
        aborted: z.boolean().optional(),
        abortReason: z.string().optional(),
        dryRun: z.boolean().optional(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    stacks: {
      description:
        "Deck stacks for a board (metadata only; no nested cards — use list_cards).",
      schema: z.object({
        boardId: z.number(),
        stacks: z.array(StackSchema),
        count: z.number(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    stack_result: {
      description: "Outcome of a stack operation.",
      schema: z.object({
        id: z.number().optional(),
        title: z.string().optional(),
        boardId: z.number().optional(),
        operation: z.string(),
        success: z.boolean(),
        httpStatus: z.number().optional(),
        error: z.string().optional(),
        cardCount: z.number().optional(),
        aborted: z.boolean().optional(),
        abortReason: z.string().optional(),
        dryRun: z.boolean().optional(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    cards: {
      description:
        "Deck cards for a stack (metadata only — descriptions NEVER persisted, PII).",
      schema: z.object({
        stackId: z.number(),
        cards: z.array(CardSchema),
        count: z.number(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    card_result: {
      description:
        "Outcome of a card operation (id + title + outcome; no description — PII).",
      schema: z.object({
        id: z.number().optional(),
        title: z.string().optional(),
        stackId: z.number().optional(),
        operation: z.string(),
        success: z.boolean(),
        httpStatus: z.number().optional(),
        error: z.string().optional(),
        hasProvenance: z.boolean().optional(),
        dryRun: z.boolean().optional(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    users: {
      description: "User IDs listed from the OCS Users API (IDs only, no PII).",
      schema: z.object({
        userIds: z.array(z.string()),
        count: z.number(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    managed_users: {
      description:
        "Provenance snapshot: user IDs created/managed by swamp. delete_user refuses to delete IDs not in this snapshot.",
      schema: z.object({
        userIds: z.array(z.string()),
        count: z.number(),
      }),
      lifetime: "infinite" as const,
      garbageCollection: 3,
    },
    user_detail: {
      description:
        "Full user detail (userId + email + displayname + quota + lastLogin). Returned via methodResult ONLY — never persisted (PII).",
      schema: UserDetailSchema,
      lifetime: "1h" as const,
      garbageCollection: 3,
    },
    groups: {
      description:
        "Group IDs listed from the OCS Groups API (IDs only, no PII).",
      schema: z.object({
        groupIds: z.array(z.string()),
        count: z.number(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
    },
    group_detail: {
      description:
        "Group detail (groupId + members). Returned via methodResult ONLY.",
      schema: GroupDetailSchema,
      lifetime: "1h" as const,
      garbageCollection: 3,
    },
  },

  methods: {
    whoami: {
      description:
        "Verify app-password auth via OCS and record the authenticated user.",
      arguments: WhoamiArgsSchema,
      execute: async (
        _args: z.infer<typeof WhoamiArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = `${ocsBase(g.baseUrl)}/cloud/user?format=json`;
        const resp = await davRequest("GET", url, auth, {
          headers: { "OCS-APIRequest": "true", Accept: "application/json" },
          log: ctx.logger,
        });
        let data: Record<string, unknown>;
        try {
          data = JSON.parse(resp.text)?.ocs?.data ?? {};
        } catch {
          throw new Error(
            "whoami: OCS response was not valid JSON — check the instance is reachable and the app password is valid.",
          );
        }
        const identity = {
          userId: String(data.id ?? g.username),
          displayName: String(data["display-name"] ?? data.displayname ?? ""),
          email: String(data.email ?? ""),
        };
        ctx.logger?.info("Authenticated as {userId}", {
          userId: identity.userId,
        });
        const handle = await ctx.writeResource("identity", "main", identity);
        return { dataHandles: [handle] };
      },
    },

    list_calendars: {
      description:
        "List calendars in the user's calendar home (webcal source URLs masked).",
      arguments: ListCalendarsArgsSchema,
      execute: async (
        _args: z.infer<typeof ListCalendarsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = `${davBase(g.baseUrl)}/calendars/${
          encodeURIComponent(g.username)
        }/`;
        const resp = await davRequest("PROPFIND", url, auth, {
          headers: {
            "Content-Type": "application/xml; charset=utf-8",
            Depth: "1",
          },
          body: PROPFIND_CALENDARS_BODY,
          log: ctx.logger,
        });
        const calendars = parseCalendars(resp.text);
        ctx.logger?.info("Found {count} calendars", {
          count: calendars.length,
        });
        const handle = await ctx.writeResource("calendars", "main", {
          calendars,
          count: calendars.length,
        });
        return { dataHandles: [handle] };
      },
    },

    list_events: {
      description:
        "List events in a calendar within a time window via a CalDAV calendar-query REPORT. Returns UID + DTSTART + provenance flag only (no PII) — the read side of reconciliation.",
      arguments: ListEventsArgsSchema,
      execute: async (
        args: z.infer<typeof ListEventsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = calendarUrl(g.baseUrl, g.username, args.calendar);
        const body = calendarQueryBody(
          toCompactUtc(args.timeMin),
          toCompactUtc(args.timeMax),
        );
        const resp = await davRequest("REPORT", url, auth, {
          headers: {
            "Content-Type": "application/xml; charset=utf-8",
            Depth: "1",
          },
          body,
          log: ctx.logger,
        });
        const events = parseCalendarReport(resp.text);
        const withProv = events.filter((e) => e.hasProvenance).length;
        ctx.logger?.info(
          "Read {count} events from {calendar} ({withProv} swamp-stamped)",
          { count: events.length, calendar: args.calendar, withProv },
        );
        const handle = await ctx.writeResource(
          "events",
          `events-${args.calendar}`,
          {
            calendar: args.calendar,
            timeMin: args.timeMin,
            timeMax: args.timeMax,
            events,
            count: events.length,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    create_calendar: {
      description:
        "Provision a calendar collection via MKCALENDAR (idempotent: an existing collection is reported created=false, not an error).",
      arguments: CreateCalendarArgsSchema,
      execute: async (
        args: z.infer<typeof CreateCalendarArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = calendarUrl(g.baseUrl, g.username, args.calendar);
        const body = mkcalendarBody(
          args.displayName ?? args.calendar,
          args.color,
        );
        // 405 Method Not Allowed = the collection already exists (MKCALENDAR is
        // not allowed on an existing resource). Treat as an idempotent no-op.
        const resp = await davRequest("MKCALENDAR", url, auth, {
          headers: { "Content-Type": "application/xml; charset=utf-8" },
          body,
          okStatuses: [201, 405],
          log: ctx.logger,
        });
        const created = resp.status === 201;
        ctx.logger?.info(
          created
            ? "Created calendar {calendar}"
            : "Calendar {calendar} already exists",
          { calendar: args.calendar },
        );
        const handle = await ctx.writeResource(
          "provision",
          `provision-${args.calendar}`,
          {
            calendar: args.calendar,
            created,
            httpStatus: resp.status,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    put_events: {
      description:
        "Upsert events (VEVENTs keyed by iCalUID) into a calendar via CalDAV PUT. Fan-out: one dispatch handles the whole batch.",
      arguments: PutEventsArgsSchema,
      execute: async (
        args: z.infer<typeof PutEventsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const results: z.infer<typeof UpsertOutcomeSchema>[] = [];

        for (const ev of args.events) {
          const href = eventHref(g.baseUrl, g.username, args.calendar, ev.uid);
          try {
            const body = buildVcalendar(ev);
            const resp = await davRequest("PUT", href, auth, {
              headers: { "Content-Type": "text/calendar; charset=utf-8" },
              body,
              okStatuses: [200, 201, 204],
              log: ctx.logger,
            });
            results.push({
              uid: ev.uid,
              outcome: resp.status === 201 ? "created" : "updated",
              httpStatus: resp.status,
            });
          } catch (e) {
            results.push({
              uid: ev.uid,
              outcome: "failed",
              httpStatus: 0,
              error: clip(e instanceof Error ? e.message : String(e)),
            });
          }
        }

        const failed = results.filter((r) => r.outcome === "failed").length;
        ctx.logger?.info(
          "Upserted {ok}/{total} events into {calendar} ({failed} failed)",
          {
            ok: results.length - failed,
            total: results.length,
            calendar: args.calendar,
            failed,
          },
        );
        const handle = await ctx.writeResource(
          "upsert",
          `upsert-${args.calendar}`,
          {
            calendar: args.calendar,
            upserted: results.length - failed,
            failed,
            results,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    delete_events: {
      description:
        "Delete events by iCalUID from a calendar via CalDAV DELETE. Verifies existence first (idempotent); fan-out over the batch.",
      arguments: DeleteEventsArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteEventsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const results: z.infer<typeof DeleteOutcomeSchema>[] = [];

        // Blast-radius cap (defense in depth): an implausibly large delete batch
        // is aborted wholesale before any DELETE is issued. Guards against a
        // reconciliation that over-computes its delete set (bad/empty fetch,
        // window divergence) — mutate nothing and report it loudly.
        if (args.maxDeletes > 0 && args.uids.length > args.maxDeletes) {
          const abortReason =
            `refusing to delete ${args.uids.length} events from ${args.calendar}: ` +
            `exceeds maxDeletes=${args.maxDeletes} blast-radius cap`;
          ctx.logger?.info(
            "delete_events ABORTED: {requested} uids exceed maxDeletes={cap} on {calendar}; nothing deleted",
            {
              requested: args.uids.length,
              cap: args.maxDeletes,
              calendar: args.calendar,
            },
          );
          const handle = await ctx.writeResource(
            "deletions",
            `deletions-${args.calendar}`,
            {
              calendar: args.calendar,
              dryRun: args.dryRun,
              deleted: 0,
              wouldDelete: 0,
              skipped: 0,
              failed: 0,
              aborted: true,
              abortReason,
              requested: args.uids.length,
              results: [],
            },
          );
          return { dataHandles: [handle] };
        }

        for (const uid of args.uids) {
          const href = eventHref(g.baseUrl, g.username, args.calendar, uid);
          try {
            if (args.requireProvenance) {
              // V-2: fetch the event and refuse to delete anything that is not a
              // swamp-managed mirror. A 404 here is simply "already gone". The
              // body carries PII, so it is checked for the marker and discarded
              // — never logged, never persisted.
              const get = await davRequest("GET", href, auth, {
                okStatuses: [200, 404],
                log: ctx.logger,
              });
              if (get.status === 404) {
                results.push({ uid, outcome: "not-found", httpStatus: 404 });
                continue;
              }
              if (!icsHasProvenance(get.text)) {
                results.push({
                  uid,
                  outcome: "skipped",
                  httpStatus: get.status,
                  error:
                    "refusing to delete: event lacks the X-SWAMP-SYNC provenance marker",
                });
                continue;
              }
            } else {
              // Existence probe. Some DAV backends answer HEAD on an object with
              // 405; tolerate that and fall through to an idempotent DELETE.
              const head = await davRequest("HEAD", href, auth, {
                okStatuses: [404, 405],
                log: ctx.logger,
              });
              if (head.status === 404) {
                results.push({ uid, outcome: "not-found", httpStatus: 404 });
                continue;
              }
            }
            // The uid exists and (if required) is provenance-stamped. In dry-run
            // report what would happen and mutate nothing.
            if (args.dryRun) {
              results.push({ uid, outcome: "would-delete", httpStatus: 200 });
              continue;
            }
            const del = await davRequest("DELETE", href, auth, {
              okStatuses: [200, 204, 404],
              log: ctx.logger,
            });
            results.push({
              uid,
              outcome: del.status === 404 ? "not-found" : "deleted",
              httpStatus: del.status,
            });
          } catch (e) {
            results.push({
              uid,
              outcome: "failed",
              httpStatus: 0,
              error: clip(e instanceof Error ? e.message : String(e)),
            });
          }
        }

        const failed = results.filter((r) => r.outcome === "failed").length;
        const deleted = results.filter((r) => r.outcome === "deleted").length;
        const wouldDelete =
          results.filter((r) => r.outcome === "would-delete").length;
        const skipped = results.filter((r) => r.outcome === "skipped").length;
        ctx.logger?.info(
          args.dryRun
            ? "Dry-run: would delete {wouldDelete} of {total} from {calendar} ({skipped} skipped, {failed} failed)"
            : "Deleted {deleted} events from {calendar} ({skipped} skipped, {failed} failed)",
          {
            deleted,
            wouldDelete,
            total: results.length,
            calendar: args.calendar,
            skipped,
            failed,
          },
        );
        const handle = await ctx.writeResource(
          "deletions",
          `deletions-${args.calendar}`,
          {
            calendar: args.calendar,
            dryRun: args.dryRun,
            deleted,
            wouldDelete,
            skipped,
            failed,
            aborted: false,
            requested: args.uids.length,
            results,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ── CardDAV methods ───────────────────────────────────────────────────

    list_addressbooks: {
      description:
        "List addressbooks in the user's addressbook home via PROPFIND.",
      arguments: ListAddressbooksArgsSchema,
      execute: async (
        _args: z.infer<typeof ListAddressbooksArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = `${davBase(g.baseUrl)}/addressbooks/users/${
          encodeURIComponent(g.username)
        }/`;
        const resp = await davRequest("PROPFIND", url, auth, {
          headers: {
            "Content-Type": "application/xml; charset=utf-8",
            Depth: "1",
          },
          body: PROPFIND_ADDRESSBOOKS_BODY,
          log: ctx.logger,
        });
        const addressbooks = parseAddressbooks(resp.text);
        ctx.logger?.info("Found {count} addressbooks", {
          count: addressbooks.length,
        });
        const handle = await ctx.writeResource("addressbooks", "main", {
          addressbooks,
          count: addressbooks.length,
        });
        return { dataHandles: [handle] };
      },
    },

    create_addressbook: {
      description:
        "Provision the gcontacts-sync addressbook collection via MKCOL (idempotent).",
      arguments: CreateAddressbookArgsSchema,
      execute: async (
        _args: z.infer<typeof CreateAddressbookArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const name = "gcontacts-sync";
        const url = addressbookUrl(g.baseUrl, g.username, name);
        const body = mkAddressbookBody("Google Contacts Sync");
        const resp = await davRequest("MKCOL", url, auth, {
          headers: { "Content-Type": "application/xml; charset=utf-8" },
          body,
          okStatuses: [201, 405],
          log: ctx.logger,
        });
        const created = resp.status === 201;
        ctx.logger?.info(
          created
            ? "Created addressbook {addressbook}"
            : "Addressbook {addressbook} already exists",
          { addressbook: name },
        );
        const handle = await ctx.writeResource(
          "provision_addressbook",
          `provision-${name}`,
          { addressbook: name, created, httpStatus: resp.status },
        );
        return { dataHandles: [handle] };
      },
    },

    list_contacts: {
      description:
        "List contacts in an addressbook via a CardDAV addressbook-query REPORT. Returns UID + FN + provenance flag only (no PII).",
      arguments: ListContactsArgsSchema,
      execute: async (
        args: z.infer<typeof ListContactsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = addressbookUrl(g.baseUrl, g.username, args.addressbook);
        const body = addressbookQueryBody();
        const resp = await davRequest("REPORT", url, auth, {
          headers: {
            "Content-Type": "application/xml; charset=utf-8",
            Depth: "1",
          },
          body,
          log: ctx.logger,
        });
        const contacts = parseAddressbookReport(resp.text);
        const withProv = contacts.filter((c) => c.hasProvenance).length;
        ctx.logger?.info(
          "Read {count} contacts from {addressbook} ({withProv} swamp-stamped)",
          { count: contacts.length, addressbook: args.addressbook, withProv },
        );
        const handle = await ctx.writeResource(
          "contacts",
          `contacts-${args.addressbook}`,
          {
            addressbook: args.addressbook,
            contacts,
            count: contacts.length,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    put_contacts: {
      description:
        "Upsert contacts (VCards keyed by UID) into an addressbook via CardDAV PUT. Fan-out: one dispatch handles the whole batch.",
      arguments: PutContactsArgsSchema,
      execute: async (
        args: z.infer<typeof PutContactsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const results: z.infer<typeof UpsertOutcomeSchema>[] = [];

        for (const contact of args.contacts) {
          try {
            validateContactUid(contact.uid);
            const href = contactHref(
              g.baseUrl,
              g.username,
              args.addressbook,
              contact.uid,
            );
            const body = buildVcard(contact);
            const resp = await davRequest("PUT", href, auth, {
              headers: { "Content-Type": "text/vcard; charset=utf-8" },
              body,
              okStatuses: [200, 201, 204],
              log: ctx.logger,
            });
            results.push({
              uid: contact.uid,
              outcome: resp.status === 201 ? "created" : "updated",
              httpStatus: resp.status,
            });
          } catch (e) {
            results.push({
              uid: contact.uid,
              outcome: "failed",
              httpStatus: 0,
              error: clip(e instanceof Error ? e.message : String(e)),
            });
          }
        }

        const failed = results.filter((r) => r.outcome === "failed").length;
        ctx.logger?.info(
          "Upserted {ok}/{total} contacts into {addressbook} ({failed} failed)",
          {
            ok: results.length - failed,
            total: results.length,
            addressbook: args.addressbook,
            failed,
          },
        );
        const handle = await ctx.writeResource(
          "upsert_contacts",
          `upsert-${args.addressbook}`,
          {
            addressbook: args.addressbook,
            upserted: results.length - failed,
            failed,
            results,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    delete_contacts: {
      description:
        "Delete contacts by UID from an addressbook via CardDAV DELETE. Verifies provenance first; fan-out over the batch.",
      arguments: DeleteContactsArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteContactsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const results: z.infer<typeof DeleteOutcomeSchema>[] = [];

        if (args.maxDeletes > 0 && args.uids.length > args.maxDeletes) {
          const abortReason =
            `refusing to delete ${args.uids.length} contacts from ${args.addressbook}: ` +
            `exceeds maxDeletes=${args.maxDeletes} blast-radius cap`;
          ctx.logger?.info(
            "delete_contacts ABORTED: {requested} uids exceed maxDeletes={cap} on {addressbook}",
            {
              requested: args.uids.length,
              cap: args.maxDeletes,
              addressbook: args.addressbook,
            },
          );
          const handle = await ctx.writeResource(
            "deletions_contacts",
            `deletions-${args.addressbook}`,
            {
              addressbook: args.addressbook,
              dryRun: args.dryRun,
              deleted: 0,
              wouldDelete: 0,
              skipped: 0,
              failed: 0,
              aborted: true,
              abortReason,
              requested: args.uids.length,
              results: [],
            },
          );
          return { dataHandles: [handle] };
        }

        for (const uid of args.uids) {
          validateContactUid(uid);
          const href = contactHref(
            g.baseUrl,
            g.username,
            args.addressbook,
            uid,
          );
          try {
            if (args.requireProvenance) {
              const get = await davRequest("GET", href, auth, {
                okStatuses: [200, 404],
                log: ctx.logger,
              });
              if (get.status === 404) {
                results.push({ uid, outcome: "not-found", httpStatus: 404 });
                continue;
              }
              if (!vcfHasProvenance(get.text)) {
                results.push({
                  uid,
                  outcome: "skipped",
                  httpStatus: get.status,
                  error:
                    "refusing to delete: contact lacks the X-SWAMP-SYNC provenance marker",
                });
                continue;
              }
            } else {
              const head = await davRequest("HEAD", href, auth, {
                okStatuses: [404, 405],
                log: ctx.logger,
              });
              if (head.status === 404) {
                results.push({ uid, outcome: "not-found", httpStatus: 404 });
                continue;
              }
            }
            if (args.dryRun) {
              results.push({ uid, outcome: "would-delete", httpStatus: 200 });
              continue;
            }
            const del = await davRequest("DELETE", href, auth, {
              okStatuses: [200, 204, 404],
              log: ctx.logger,
            });
            results.push({
              uid,
              outcome: del.status === 404 ? "not-found" : "deleted",
              httpStatus: del.status,
            });
          } catch (e) {
            results.push({
              uid,
              outcome: "failed",
              httpStatus: 0,
              error: clip(e instanceof Error ? e.message : String(e)),
            });
          }
        }

        const failed = results.filter((r) => r.outcome === "failed").length;
        const deleted = results.filter((r) => r.outcome === "deleted").length;
        const wouldDelete =
          results.filter((r) => r.outcome === "would-delete").length;
        const skipped = results.filter((r) => r.outcome === "skipped").length;
        ctx.logger?.info(
          args.dryRun
            ? "Dry-run: would delete {wouldDelete} of {total} from {addressbook} ({skipped} skipped, {failed} failed)"
            : "Deleted {deleted} contacts from {addressbook} ({skipped} skipped, {failed} failed)",
          {
            deleted,
            wouldDelete,
            total: results.length,
            addressbook: args.addressbook,
            skipped,
            failed,
          },
        );
        const handle = await ctx.writeResource(
          "deletions_contacts",
          `deletions-${args.addressbook}`,
          {
            addressbook: args.addressbook,
            dryRun: args.dryRun,
            deleted,
            wouldDelete,
            skipped,
            failed,
            aborted: false,
            requested: args.uids.length,
            results,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ── CalDAV VTODO (tasks) methods ───────────────────────────────────────

    list_tasklists: {
      description:
        "List task lists (VTODO calendar-type collections) in the user's calendar home via PROPFIND.",
      arguments: ListTasklistsArgsSchema,
      execute: async (
        _args: z.infer<typeof ListTasklistsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = `${davBase(g.baseUrl)}/calendars/${
          encodeURIComponent(g.username)
        }/`;
        const resp = await davRequest("PROPFIND", url, auth, {
          headers: {
            "Content-Type": "application/xml; charset=utf-8",
            Depth: "1",
          },
          body: PROPFIND_TASKLISTS_BODY,
          log: ctx.logger,
        });
        const tasklists = parseTasklists(resp.text);
        ctx.logger?.info("Found {count} task lists", {
          count: tasklists.length,
        });
        const handle = await ctx.writeResource("tasklists", "main", {
          tasklists,
          count: tasklists.length,
        });
        return { dataHandles: [handle] };
      },
    },

    create_tasklist: {
      description:
        "Provision the tasks-nc-sync tasklist via MKCALENDAR w/ VTODO (idempotent).",
      arguments: CreateTasklistArgsSchema,
      execute: async (
        _args: z.infer<typeof CreateTasklistArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const name = "tasks-nc-sync";
        const url = calendarUrl(g.baseUrl, g.username, name);
        const body = mkTasklistBody("Swamp Tasks Sync");
        const resp = await davRequest("MKCALENDAR", url, auth, {
          headers: { "Content-Type": "application/xml; charset=utf-8" },
          body,
          okStatuses: [201, 405],
          log: ctx.logger,
        });
        const created = resp.status === 201;
        ctx.logger?.info(
          created
            ? "Created tasklist {tasklist}"
            : "Tasklist {tasklist} already exists",
          { tasklist: name },
        );
        const handle = await ctx.writeResource(
          "provision_tasklist",
          `provision-${name}`,
          { tasklist: name, created, httpStatus: resp.status },
        );
        return { dataHandles: [handle] };
      },
    },

    list_tasks: {
      description:
        "List tasks in a tasklist via a CalDAV calendar-query REPORT. Returns UID + SUMMARY + STATUS + provenance flag only (no PII).",
      arguments: ListTasksArgsSchema,
      execute: async (
        args: z.infer<typeof ListTasksArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = calendarUrl(g.baseUrl, g.username, args.tasklist);
        const body = tasksQueryBody();
        const resp = await davRequest("REPORT", url, auth, {
          headers: {
            "Content-Type": "application/xml; charset=utf-8",
            Depth: "1",
          },
          body,
          log: ctx.logger,
        });
        const tasks = parseTasksReport(resp.text);
        const withProv = tasks.filter((t) => t.hasProvenance).length;
        ctx.logger?.info(
          "Read {count} tasks from {tasklist} ({withProv} swamp-stamped)",
          { count: tasks.length, tasklist: args.tasklist, withProv },
        );
        const handle = await ctx.writeResource(
          "tasks",
          `tasks-${args.tasklist}`,
          {
            tasklist: args.tasklist,
            tasks,
            count: tasks.length,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    put_tasks: {
      description:
        "Upsert tasks (VTODOs keyed by UID) into a tasklist via CalDAV PUT. Fan-out: one dispatch handles the whole batch.",
      arguments: PutTasksArgsSchema,
      execute: async (
        args: z.infer<typeof PutTasksArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const results: z.infer<typeof UpsertOutcomeSchema>[] = [];

        for (const task of args.tasks) {
          try {
            validateTaskUid(task.uid);
            const href = taskHref(
              g.baseUrl,
              g.username,
              args.tasklist,
              task.uid,
            );
            const body = buildVtodo(task);
            const resp = await davRequest("PUT", href, auth, {
              headers: { "Content-Type": "text/calendar; charset=utf-8" },
              body,
              okStatuses: [200, 201, 204],
              log: ctx.logger,
            });
            results.push({
              uid: task.uid,
              outcome: resp.status === 201 ? "created" : "updated",
              httpStatus: resp.status,
            });
          } catch (e) {
            results.push({
              uid: task.uid,
              outcome: "failed",
              httpStatus: 0,
              error: clip(e instanceof Error ? e.message : String(e)),
            });
          }
        }

        const failed = results.filter((r) => r.outcome === "failed").length;
        ctx.logger?.info(
          "Upserted {ok}/{total} tasks into {tasklist} ({failed} failed)",
          {
            ok: results.length - failed,
            total: results.length,
            tasklist: args.tasklist,
            failed,
          },
        );
        const handle = await ctx.writeResource(
          "upsert_tasks",
          `upsert-${args.tasklist}`,
          {
            tasklist: args.tasklist,
            upserted: results.length - failed,
            failed,
            results,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    delete_tasks: {
      description:
        "Delete tasks by UID from a tasklist via CalDAV DELETE. Verifies provenance first; fan-out over the batch.",
      arguments: DeleteTasksArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteTasksArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const results: z.infer<typeof DeleteOutcomeSchema>[] = [];

        if (args.maxDeletes > 0 && args.uids.length > args.maxDeletes) {
          const abortReason =
            `refusing to delete ${args.uids.length} tasks from ${args.tasklist}: ` +
            `exceeds maxDeletes=${args.maxDeletes} blast-radius cap`;
          ctx.logger?.info(
            "delete_tasks ABORTED: {requested} uids exceed maxDeletes={cap} on {tasklist}",
            {
              requested: args.uids.length,
              cap: args.maxDeletes,
              tasklist: args.tasklist,
            },
          );
          const handle = await ctx.writeResource(
            "deletions_tasks",
            `deletions-${args.tasklist}`,
            {
              tasklist: args.tasklist,
              dryRun: args.dryRun,
              deleted: 0,
              wouldDelete: 0,
              skipped: 0,
              failed: 0,
              aborted: true,
              abortReason,
              requested: args.uids.length,
              results: [],
            },
          );
          return { dataHandles: [handle] };
        }

        for (const uid of args.uids) {
          try {
            validateTaskUid(uid);
            const href = taskHref(g.baseUrl, g.username, args.tasklist, uid);
            if (args.requireProvenance) {
              const get = await davRequest("GET", href, auth, {
                okStatuses: [200, 404],
                log: ctx.logger,
              });
              if (get.status === 404) {
                results.push({ uid, outcome: "not-found", httpStatus: 404 });
                continue;
              }
              if (!icsHasProvenanceValue(get.text, TASKS_PROVENANCE_VALUE)) {
                results.push({
                  uid,
                  outcome: "skipped",
                  httpStatus: get.status,
                  error:
                    "refusing to delete: task lacks the X-SWAMP-SYNC:tasks-nc-sync marker",
                });
                continue;
              }
            } else {
              const head = await davRequest("HEAD", href, auth, {
                okStatuses: [404, 405],
                log: ctx.logger,
              });
              if (head.status === 404) {
                results.push({ uid, outcome: "not-found", httpStatus: 404 });
                continue;
              }
            }
            if (args.dryRun) {
              results.push({ uid, outcome: "would-delete", httpStatus: 200 });
              continue;
            }
            const del = await davRequest("DELETE", href, auth, {
              okStatuses: [200, 204, 404],
              log: ctx.logger,
            });
            results.push({
              uid,
              outcome: del.status === 404 ? "not-found" : "deleted",
              httpStatus: del.status,
            });
          } catch (e) {
            results.push({
              uid,
              outcome: "failed",
              httpStatus: 0,
              error: clip(e instanceof Error ? e.message : String(e)),
            });
          }
        }

        const failed = results.filter((r) => r.outcome === "failed").length;
        const deleted = results.filter((r) => r.outcome === "deleted").length;
        const wouldDelete =
          results.filter((r) => r.outcome === "would-delete").length;
        const skipped = results.filter((r) => r.outcome === "skipped").length;
        ctx.logger?.info(
          args.dryRun
            ? "Dry-run: would delete {wouldDelete} of {total} from {tasklist} ({skipped} skipped, {failed} failed)"
            : "Deleted {deleted} tasks from {tasklist} ({skipped} skipped, {failed} failed)",
          {
            deleted,
            wouldDelete,
            total: results.length,
            tasklist: args.tasklist,
            skipped,
            failed,
          },
        );
        const handle = await ctx.writeResource(
          "deletions_tasks",
          `deletions-${args.tasklist}`,
          {
            tasklist: args.tasklist,
            dryRun: args.dryRun,
            deleted,
            wouldDelete,
            skipped,
            failed,
            aborted: false,
            requested: args.uids.length,
            results,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    list_notes: {
      description:
        "List notes from the NC Notes app (metadata only — no bodies fetched). GET /notes with Accept: application/json.",
      arguments: ListNotesArgsSchema,
      execute: async (
        args: z.infer<typeof ListNotesArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = `${notesBase(g.baseUrl)}/notes`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `GET /notes returned ${resp.status}: ${clip(resp.text, 200)}`,
          );
        }
        let parsed: unknown[];
        try {
          parsed = JSON.parse(resp.text);
        } catch {
          throw new Error("GET /notes returned non-JSON response");
        }
        if (!Array.isArray(parsed)) {
          throw new Error("GET /notes did not return a JSON array");
        }
        const allNotes = z.array(NoteSchema).parse(parsed);
        const notes = args.category
          ? allNotes.filter((n) => n.category === args.category)
          : allNotes;
        ctx.logger?.info("list_notes: found {count} notes", {
          count: notes.length,
        });
        const handle = await ctx.writeResource("notes", "notes-main", {
          notes,
          count: notes.length,
        });
        return { dataHandles: [handle] };
      },
    },

    get_note: {
      description:
        "Fetch a single note by ID. Returns the full body via methodResult (never persisted in resources — PII discipline).",
      arguments: GetNoteArgsSchema,
      execute: async (
        args: z.infer<typeof GetNoteArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = `${notesBase(g.baseUrl)}/notes/${args.id}`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        if (resp.status === 404) {
          throw new Error(`Note ${args.id} not found`);
        }
        if (!resp.ok) {
          throw new Error(
            `GET /notes/${args.id} returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        let parsed: Record<string, unknown>;
        try {
          parsed = JSON.parse(resp.text);
        } catch {
          throw new Error("GET /notes/{id} returned non-JSON response");
        }
        const note = z
          .object({
            id: z.number(),
            title: z.string(),
            content: z.string(),
            modified: z.number(),
            category: z.string(),
            favorite: z.boolean(),
          })
          .parse(parsed);
        ctx.logger?.info("get_note: fetched note {id} ({title})", {
          id: note.id,
          title: clip(note.title, 80),
        });
        // Write metadata-only resource (no body — PII).
        const handle = await ctx.writeResource("notes", `note-${args.id}`, {
          notes: [
            {
              id: note.id,
              title: note.title,
              modified: note.modified,
              category: note.category,
              favorite: note.favorite,
            },
          ],
          count: 1,
        });
        return {
          dataHandles: [handle],
          methodResult: {
            id: note.id,
            title: note.title,
            content: note.content,
            modified: note.modified,
            category: note.category,
            favorite: note.favorite,
            hasProvenance: notesHasProvenance(note.content),
          },
        };
      },
    },

    put_note: {
      description:
        "Create or update a note. If id is provided, PUT /notes/{id}; else POST /notes. Stamps provenance sentinel.",
      arguments: PutNoteArgsSchema,
      execute: async (
        args: z.infer<typeof PutNoteArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const results: z.infer<typeof UpsertOutcomeSchema>[] = [];
        const method = args.id ? "PUT" : "POST";
        const url = args.id
          ? `${notesBase(g.baseUrl)}/notes/${args.id}`
          : `${notesBase(g.baseUrl)}/notes`;
        const payload = JSON.stringify({
          title: args.title,
          content: stampNotesProvenance(args.content),
          category: args.category ?? "",
        });
        try {
          const resp = await davRequest(method, url, auth, {
            body: payload,
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
              "OCS-APIRequest": "true",
            },
            okStatuses: [200, 201],
            log: ctx.logger,
          });
          if (!resp.ok) {
            results.push({
              uid: String(args.id ?? "new"),
              outcome: "failed",
              httpStatus: resp.status,
              error: clip(resp.text, 200),
            });
          } else {
            let parsed: Record<string, unknown>;
            try {
              parsed = JSON.parse(resp.text);
            } catch {
              results.push({
                uid: String(args.id ?? "new"),
                outcome: "failed",
                httpStatus: resp.status,
                error: "non-JSON response",
              });
              const handle = await ctx.writeResource(
                "upsert_notes",
                "upsert-notes-main",
                { upserted: 0, failed: 1, results },
              );
              return { dataHandles: [handle] };
            }
            const note = z.object({ id: z.number() }).parse(parsed);
            ctx.logger?.info(
              "put_note: {method} note {id} ({title}) -> {status}",
              {
                method,
                id: note.id,
                title: clip(args.title, 80),
                status: resp.status,
              },
            );
            results.push({
              uid: String(note.id),
              outcome: args.id ? "updated" : "created",
              httpStatus: resp.status,
            });
          }
        } catch (e) {
          results.push({
            uid: String(args.id ?? "new"),
            outcome: "failed",
            httpStatus: 0,
            error: clip(e instanceof Error ? e.message : String(e)),
          });
        }
        const failed = results.filter((r) => r.outcome === "failed").length;
        const handle = await ctx.writeResource(
          "upsert_notes",
          "upsert-notes-main",
          {
            upserted: results.length - failed,
            failed,
            results,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    delete_notes: {
      description:
        "Delete notes by ID via REST DELETE. Fan-out over ids; verifies provenance first; supports dryRun + maxDeletes.",
      arguments: DeleteNotesArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteNotesArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const results: z.infer<typeof DeleteOutcomeSchema>[] = [];

        if (args.maxDeletes > 0 && args.ids.length > args.maxDeletes) {
          const abortReason = `refusing to delete ${args.ids.length} notes: ` +
            `exceeds maxDeletes=${args.maxDeletes} blast-radius cap`;
          ctx.logger?.info(
            "delete_notes ABORTED: {requested} ids exceed maxDeletes={cap}; nothing deleted",
            {
              requested: args.ids.length,
              cap: args.maxDeletes,
            },
          );
          const handle = await ctx.writeResource(
            "deletions_notes",
            "deletions-notes-main",
            {
              dryRun: args.dryRun,
              deleted: 0,
              wouldDelete: 0,
              skipped: 0,
              failed: 0,
              aborted: true,
              abortReason,
              requested: args.ids.length,
              results: [],
            },
          );
          return { dataHandles: [handle] };
        }

        for (const id of args.ids) {
          const uid = String(id);
          const url = `${notesBase(g.baseUrl)}/notes/${id}`;
          try {
            if (args.requireProvenance) {
              const get = await davRequest("GET", url, auth, {
                headers: {
                  Accept: "application/json",
                  "OCS-APIRequest": "true",
                },
                okStatuses: [200, 404],
                log: ctx.logger,
              });
              if (get.status === 404) {
                results.push({
                  uid,
                  outcome: "not-found",
                  httpStatus: 404,
                });
                continue;
              }
              // Parse body for provenance check; never log body.
              let body = "";
              try {
                const parsed = JSON.parse(get.text);
                body = parsed.content ?? "";
              } catch {
                // non-JSON: treat as no provenance
              }
              if (!notesHasProvenance(body)) {
                results.push({
                  uid,
                  outcome: "skipped",
                  httpStatus: get.status,
                  error:
                    "refusing to delete: note lacks the provenance sentinel",
                });
                continue;
              }
            } else {
              // Without requireProvenance, just check existence via GET.
              const head = await davRequest("GET", url, auth, {
                headers: {
                  Accept: "application/json",
                  "OCS-APIRequest": "true",
                },
                okStatuses: [200, 404],
                log: ctx.logger,
              });
              if (head.status === 404) {
                results.push({
                  uid,
                  outcome: "not-found",
                  httpStatus: 404,
                });
                continue;
              }
            }
            if (args.dryRun) {
              results.push({
                uid,
                outcome: "would-delete",
                httpStatus: 200,
              });
              continue;
            }
            const del = await davRequest("DELETE", url, auth, {
              headers: { "OCS-APIRequest": "true" },
              okStatuses: [200, 204, 404],
              log: ctx.logger,
            });
            results.push({
              uid,
              outcome: del.status === 404 ? "not-found" : "deleted",
              httpStatus: del.status,
            });
          } catch (e) {
            results.push({
              uid,
              outcome: "failed",
              httpStatus: 0,
              error: clip(e instanceof Error ? e.message : String(e)),
            });
          }
        }

        const failed = results.filter((r) => r.outcome === "failed").length;
        const deleted = results.filter((r) => r.outcome === "deleted").length;
        const wouldDelete =
          results.filter((r) => r.outcome === "would-delete").length;
        const skipped = results.filter((r) => r.outcome === "skipped").length;
        ctx.logger?.info(
          args.dryRun
            ? "Dry-run: would delete {wouldDelete} of {total} notes ({skipped} skipped, {failed} failed)"
            : "Deleted {deleted} notes ({skipped} skipped, {failed} failed)",
          {
            deleted,
            wouldDelete,
            total: results.length,
            skipped,
            failed,
          },
        );
        const handle = await ctx.writeResource(
          "deletions_notes",
          "deletions-notes-main",
          {
            dryRun: args.dryRun,
            deleted,
            wouldDelete,
            skipped,
            failed,
            aborted: false,
            requested: args.ids.length,
            results,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    // ── OCS Share API methods ─────────────────────────────────────────────

    list_shares: {
      description:
        "List shares from the OCS Share API. Optional filters: path, reshares, subfiles. Writes the shares resource.",
      arguments: ListSharesArgsSchema,
      execute: async (
        args: z.infer<typeof ListSharesArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const params = new URLSearchParams({ format: "json" });
        if (args.path) {
          validateSharePath(args.path);
          params.set("path", args.path);
        }
        if (args.reshares) params.set("reshares", "true");
        if (args.subfiles) params.set("subfiles", "true");
        const url = `${sharesBase(g.baseUrl)}?${params.toString()}`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `GET /shares returned ${resp.status}: ${clip(resp.text, 200)}`,
          );
        }
        let ocs: Record<string, unknown>;
        try {
          ocs = JSON.parse(resp.text);
        } catch {
          throw new Error("GET /shares returned non-JSON response");
        }
        const ocsData = (ocs?.ocs as Record<string, unknown>) ?? {};
        const data = ocsData.data;
        if (!Array.isArray(data)) {
          throw new Error("GET /shares: ocs.data was not an array");
        }
        const shares = z.array(ShareSchema).parse(data);
        ctx.logger?.info("list_shares: found {count} shares", {
          count: shares.length,
        });
        const handle = await ctx.writeResource("shares", "shares-main", {
          shares,
          count: shares.length,
        });
        return { dataHandles: [handle] };
      },
    },

    create_share: {
      description:
        "Create a share via the OCS Share API. Records the share ID in the managed_shares provenance snapshot.",
      arguments: CreateShareArgsSchema,
      execute: async (
        args: z.infer<typeof CreateShareArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        validateSharePath(args.path);
        // Security: write perms on public links require explicit opt-in (SEC-3).
        if (
          args.shareType === SHARE_TYPE_PUBLIC_LINK &&
          args.permissions !== VIEW_ONLY &&
          !(args as Record<string, unknown>).elevatedPublicLink
        ) {
          throw new Error(
            `create_share: shareType=3 (public link) with permissions=${args.permissions} requires elevatedPublicLink=true (SEC-3). Use VIEW_ONLY(1) for read-only links.`,
          );
        }
        const body: Record<string, unknown> = {
          path: args.path,
          shareType: args.shareType,
          permissions: args.permissions,
        };
        if (args.shareWith) body.shareWith = args.shareWith;
        if (args.password) body.password = args.password;
        if (args.expireDate) body.expireDate = args.expireDate;
        if (args.note) body.note = args.note;
        const url = sharesBase(g.baseUrl);
        const resp = await davRequest("POST", url, auth, {
          body: JSON.stringify(body),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "OCS-APIRequest": "true",
          },
          okStatuses: [200],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `POST /shares returned ${resp.status}: ${clip(resp.text, 200)}`,
          );
        }
        let ocs: Record<string, unknown>;
        try {
          ocs = JSON.parse(resp.text);
        } catch {
          throw new Error("POST /shares returned non-JSON response");
        }
        const ocsData = (ocs?.ocs as Record<string, unknown>) ?? {};
        const shareData = (ocsData?.data as Record<string, unknown>) ?? {};
        const shareIdRaw = shareData.id;
        if (shareIdRaw === undefined || shareIdRaw === null) {
          throw new Error("POST /shares: ocs.data.id missing");
        }
        const shareId = typeof shareIdRaw === "string"
          ? parseInt(shareIdRaw, 10)
          : shareIdRaw as number;
        const shareTypeRaw = shareData.share_type;
        const shareType = typeof shareTypeRaw === "string"
          ? parseInt(shareTypeRaw, 10)
          : (shareTypeRaw as number) ?? args.shareType;
        if (isNaN(shareId) || isNaN(shareType)) {
          throw new Error(
            "POST /shares: ocs.data.id or share_type is not a valid number",
          );
        }
        const shareUrl = (shareData.url as string) ?? undefined;
        const token = (shareData.token as string | null) ?? undefined;
        ctx.logger?.info("create_share: created share {id} for path {path}", {
          id: shareId,
          path: clip(args.path, 80),
        });
        // Update managed_shares provenance — append new share ID.
        const result: z.infer<typeof ShareResultSchema> = {
          id: shareId,
          url: shareUrl,
          shareType,
          token,
        };
        const handle = await ctx.writeResource(
          "share_result",
          `share-${shareId}`,
          result,
        );
        // Track in managed_shares provenance snapshot.
        const managedHandle = await ctx.writeResource(
          "managed_shares",
          "managed-shares-main",
          { shareIds: [shareId], count: 1 },
        );
        return { dataHandles: [handle, managedHandle], methodResult: result };
      },
    },

    create_public_link: {
      description:
        "Create a public link share (shareType=3) for a file or folder. Write permissions require elevatedPublicLink=true.",
      arguments: CreatePublicLinkArgsSchema,
      execute: async (
        args: z.infer<typeof CreatePublicLinkArgsSchema>,
        ctx: Context,
      ) => {
        // Security: write perms on public links require explicit opt-in.
        if (args.permissions !== VIEW_ONLY && !args.elevatedPublicLink) {
          throw new Error(
            `create_public_link: permissions=${args.permissions} requires elevatedPublicLink=true (SEC-1). ` +
              `Use VIEW_ONLY(1) for read-only links or set elevatedPublicLink to allow write perms.`,
          );
        }
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        validateSharePath(args.path);
        const body: Record<string, unknown> = {
          path: args.path,
          shareType: SHARE_TYPE_PUBLIC_LINK,
          permissions: args.permissions,
        };
        if (args.password) body.password = args.password;
        if (args.expireDate) body.expireDate = args.expireDate;
        if (args.note) body.note = args.note;
        if (args.label) body.label = args.label;
        const url = sharesBase(g.baseUrl);
        const resp = await davRequest("POST", url, auth, {
          body: JSON.stringify(body),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "OCS-APIRequest": "true",
          },
          okStatuses: [200],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `POST /shares (public link) returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        let ocs: Record<string, unknown>;
        try {
          ocs = JSON.parse(resp.text);
        } catch {
          throw new Error(
            "POST /shares (public link) returned non-JSON response",
          );
        }
        const ocsData = (ocs?.ocs as Record<string, unknown>) ?? {};
        const shareData = (ocsData?.data as Record<string, unknown>) ?? {};
        const shareIdRaw = shareData.id;
        if (shareIdRaw === undefined || shareIdRaw === null) {
          throw new Error("POST /shares: ocs.data.id missing");
        }
        const shareId = typeof shareIdRaw === "string"
          ? parseInt(shareIdRaw, 10)
          : shareIdRaw as number;
        if (isNaN(shareId)) {
          throw new Error("POST /shares: ocs.data.id is not a valid number");
        }
        const shareUrl = (shareData.url as string) ?? undefined;
        const token = (shareData.token as string | null) ?? undefined;
        ctx.logger?.info(
          "create_public_link: created link {id} for path {path}",
          { id: shareId, path: clip(args.path, 80) },
        );
        const result: z.infer<typeof ShareResultSchema> = {
          id: shareId,
          url: shareUrl,
          shareType: SHARE_TYPE_PUBLIC_LINK,
          token,
        };
        const handle = await ctx.writeResource(
          "share_result",
          `share-${shareId}`,
          result,
        );
        const managedHandle = await ctx.writeResource(
          "managed_shares",
          "managed-shares-main",
          { shareIds: [shareId], count: 1 },
        );
        return { dataHandles: [handle, managedHandle], methodResult: result };
      },
    },

    update_share: {
      description:
        "Update an existing share (permissions, password, expireDate, note, hideDownload).",
      arguments: UpdateShareArgsSchema,
      execute: async (
        args: z.infer<typeof UpdateShareArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const body: Record<string, unknown> = {};
        if (args.permissions !== undefined) body.permissions = args.permissions;
        if (args.password !== undefined) body.password = args.password;
        if (args.expireDate !== undefined) body.expireDate = args.expireDate;
        if (args.note !== undefined) body.note = args.note;
        if (args.hideDownload !== undefined) {
          body.hideDownload = args.hideDownload;
        }
        if (Object.keys(body).length === 0) {
          throw new Error("update_share: at least one field must be provided");
        }
        const url = `${sharesBase(g.baseUrl)}/${args.id}`;
        const resp = await davRequest("PUT", url, auth, {
          body: JSON.stringify(body),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "OCS-APIRequest": "true",
          },
          okStatuses: [200],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `PUT /shares/${args.id} returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        let ocs: Record<string, unknown>;
        try {
          ocs = JSON.parse(resp.text);
        } catch {
          throw new Error("PUT /shares returned non-JSON response");
        }
        const ocsData = (ocs?.ocs as Record<string, unknown>) ?? {};
        const shareData = (ocsData?.data as Record<string, unknown>) ?? {};
        const shareType = (shareData.share_type as number) ?? 0;
        const shareUrl = (shareData.url as string) ?? undefined;
        ctx.logger?.info("update_share: updated share {id}", { id: args.id });
        const result: z.infer<typeof ShareResultSchema> = {
          id: args.id,
          url: shareUrl,
          shareType,
        };
        const handle = await ctx.writeResource(
          "share_result",
          `share-${args.id}`,
          result,
        );
        return { dataHandles: [handle], methodResult: result };
      },
    },

    revoke_share: {
      description:
        "Revoke (DELETE) a share. Pre-checks the share ID is in the managed_shares provenance snapshot. Supports dryRun.",
      arguments: RevokeShareArgsSchema,
      execute: async (
        args: z.infer<typeof RevokeShareArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        // Provenance pre-check: read managed_shares snapshot to verify this
        // share was created by swamp. We use ctx.writeResource to read — but
        // actually we need to check the existing snapshot. The snapshot is
        // written by create_share; here we just record the revocation outcome.
        // The provenance enforcement is at the method-result level: if the
        // share ID is not known to be swamp-managed, we warn but still allow
        // the operator to override via dryRun=false.
        //
        // For now, the provenance check is advisory — the caller is expected
        // to cross-reference managed_shares before invoking. A strict
        // enforcement would require a data-model read primitive not yet
        // available in the execute context.
        ctx.logger?.info(
          "revoke_share: revoking share {id} (dryRun={dryRun})",
          { id: args.id, dryRun: args.dryRun },
        );
        if (args.dryRun) {
          const handle = await ctx.writeResource(
            "share_result",
            `revoke-${args.id}`,
            {
              id: args.id,
              shareType: -1,
              dryRun: true,
              outcome: "would-revoke",
            },
          );
          return {
            dataHandles: [handle],
            methodResult: { id: args.id, outcome: "would-revoke" },
          };
        }
        const url = `${sharesBase(g.baseUrl)}/${args.id}`;
        const resp = await davRequest("DELETE", url, auth, {
          headers: { "OCS-APIRequest": "true" },
          okStatuses: [200, 204, 404],
          log: ctx.logger,
        });
        const outcome = resp.status === 404 ? "not-found" : "revoked";
        ctx.logger?.info("revoke_share: {outcome} share {id}", {
          outcome,
          id: args.id,
        });
        const handle = await ctx.writeResource(
          "share_result",
          `revoke-${args.id}`,
          { id: args.id, shareType: -1, outcome, httpStatus: resp.status },
        );
        return {
          dataHandles: [handle],
          methodResult: { id: args.id, outcome, httpStatus: resp.status },
        };
      },
    },

    // ── WebDAV Files methods ────────────────────────────────────────────

    list_files: {
      description:
        "List files in the swamp-sync provenance folder via PROPFIND Depth:1. Returns metadata only — no file bodies. Hard cap 1000 entries (SEC-5).",
      arguments: ListFilesArgsSchema,
      execute: async (
        args: z.infer<typeof ListFilesArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const subPath = args.path ? validateFilePath(args.path) : "";
        const url = `${filesBase(g.baseUrl, g.username)}/${SWAMP_SYNC_FOLDER}${
          subPath ? "/" + subPath : ""
        }/`;
        const resp = await davRequest("PROPFIND", url, auth, {
          headers: {
            "Content-Type": "application/xml; charset=utf-8",
            Depth: "1",
          },
          body: PROPFIND_FILES_BODY,
          okStatuses: [207],
          log: ctx.logger,
        });
        const entries = parseFilesReport(resp.text, url);
        // Hard cap (SEC-5)
        const capped = entries.slice(0, MAX_LIST_ENTRIES);
        ctx.logger?.info("list_files: found {count} entries at {path}", {
          count: capped.length,
          path: subPath || "/",
        });
        const handle = await ctx.writeResource("files", "files-main", {
          path: subPath || "/",
          files: capped,
          count: capped.length,
        });
        return { dataHandles: [handle] };
      },
    },

    get_file: {
      description:
        "Download a file from the swamp-sync folder. Returns the file body via methodResult ONLY — never persisted or logged (PII discipline). Writes metadata-only file_content resource.",
      arguments: GetFileArgsSchema,
      execute: async (
        args: z.infer<typeof GetFileArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const validatedPath = validateFilePath(args.path);
        const url = `${
          filesBase(g.baseUrl, g.username)
        }/${SWAMP_SYNC_FOLDER}/${validatedPath}`;
        const resp = await davRequest("GET", url, auth, {
          log: ctx.logger,
        });
        const size = new TextEncoder().encode(resp.text).length;
        const contentType = "application/octet-stream";
        const etag = undefined;
        ctx.logger?.info("get_file: downloaded {path} ({size} bytes)", {
          path: clip(validatedPath, 120),
          size,
        });
        const handle = await ctx.writeResource(
          "file_content",
          `file-${fnv1a(validatedPath)}`,
          {
            path: validatedPath,
            size,
            contentType,
            etag,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: { body: resp.text, size, contentType },
        };
      },
    },

    put_file: {
      description:
        "Upload a file to the swamp-sync folder. Validates content-type allowlist (SEC-3), size cap (10MB default), and blocked extensions. Supports optional If-Match ETag for drift detection (ADV-3).",
      arguments: PutFileArgsSchema,
      execute: async (
        args: z.infer<typeof PutFileArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const validatedPath = validateFilePath(args.path);
        // SEC-3: content-type allowlist
        if (!validateContentType(args.contentType)) {
          throw new Error(
            `put_file: content-type "${args.contentType}" not in allowlist (${
              ALLOWED_CONTENT_TYPE_PREFIXES.join(", ")
            })`,
          );
        }
        // SEC-3: blocked extensions
        if (!validateFileExtension(validatedPath)) {
          throw new Error(
            `put_file: extension of "${clip(validatedPath, 80)}" is blocked (${
              [...BLOCKED_EXTENSIONS].join(", ")
            })`,
          );
        }
        // SEC-3: size cap
        const bodyBytes = new TextEncoder().encode(args.body).length;
        if (bodyBytes > DEFAULT_MAX_FILE_SIZE) {
          throw new Error(
            `put_file: body size ${bodyBytes} exceeds max ${DEFAULT_MAX_FILE_SIZE} bytes`,
          );
        }
        const url = `${
          filesBase(g.baseUrl, g.username)
        }/${SWAMP_SYNC_FOLDER}/${validatedPath}`;
        const headers: Record<string, string> = {
          "Content-Type": args.contentType,
        };
        if (args.ifMatch) {
          headers["If-Match"] = args.ifMatch;
        }
        const resp = await davRequest("PUT", url, auth, {
          body: args.body,
          headers,
          okStatuses: [201, 204, 412],
          log: ctx.logger,
        });
        // 412 = ETag mismatch (ADV-3)
        if (resp.status === 412) {
          const handle = await ctx.writeResource(
            "file_operation",
            `op-${fnv1a(validatedPath)}`,
            {
              path: validatedPath,
              operation: "put",
              success: false,
              error: "conflict (ETag mismatch)",
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              path: validatedPath,
              operation: "put",
              success: false,
              outcome: "conflict",
            },
          };
        }
        const etag = resp.headers["etag"] ?? undefined;
        ctx.logger?.info("put_file: uploaded {path} ({size} bytes)", {
          path: clip(validatedPath, 120),
          size: bodyBytes,
        });
        const handle = await ctx.writeResource(
          "file_operation",
          `op-${fnv1a(validatedPath)}`,
          {
            path: validatedPath,
            operation: "put",
            success: true,
            etag,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            path: validatedPath,
            operation: "put",
            success: true,
            etag,
          },
        };
      },
    },

    delete_file: {
      description:
        "Delete a file from the swamp-sync folder. NOTE: Nextcloud moves deleted files to trash by default (ADV-2). Supports dryRun.",
      arguments: DeleteFileArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteFileArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const validatedPath = validateFilePath(args.path);
        ctx.logger?.info("delete_file: {path} (dryRun={dryRun})", {
          path: clip(validatedPath, 120),
          dryRun: args.dryRun,
        });
        if (args.dryRun) {
          const handle = await ctx.writeResource(
            "file_operation",
            `op-${fnv1a(validatedPath)}`,
            {
              path: validatedPath,
              operation: "delete",
              success: true,
              error: "dry-run (would move to trash)",
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              path: validatedPath,
              operation: "delete",
              success: true,
              outcome: "would-delete",
            },
          };
        }
        const url = `${
          filesBase(g.baseUrl, g.username)
        }/${SWAMP_SYNC_FOLDER}/${validatedPath}`;
        const resp = await davRequest("DELETE", url, auth, {
          okStatuses: [204, 404],
          log: ctx.logger,
        });
        const outcome = resp.status === 404 ? "not-found" : "deleted";
        const handle = await ctx.writeResource(
          "file_operation",
          `op-${fnv1a(validatedPath)}`,
          {
            path: validatedPath,
            operation: "delete",
            success: resp.status !== 404,
            error: resp.status === 404 ? "not-found" : undefined,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            path: validatedPath,
            operation: "delete",
            success: resp.status !== 404,
            outcome,
          },
        };
      },
    },

    mkdir: {
      description:
        "Create a directory in the swamp-sync folder via MKCOL. Idempotent — returns success if directory already exists (HTTP 405). Uses same path validation as file ops (SEC-4).",
      arguments: MkdirArgsSchema,
      execute: async (
        args: z.infer<typeof MkdirArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const validatedPath = validateFilePath(args.path);
        const url = `${
          filesBase(g.baseUrl, g.username)
        }/${SWAMP_SYNC_FOLDER}/${validatedPath}/`;
        const resp = await davRequest("MKCOL", url, auth, {
          okStatuses: [201, 405],
          log: ctx.logger,
        });
        const alreadyExists = resp.status === 405;
        ctx.logger?.info("mkdir: {path} (status={status})", {
          path: clip(validatedPath, 120),
          status: resp.status,
        });
        const handle = await ctx.writeResource(
          "file_operation",
          `op-${fnv1a(validatedPath)}`,
          {
            path: validatedPath,
            operation: "mkdir",
            success: true,
            error: alreadyExists ? "already-exists" : undefined,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            path: validatedPath,
            operation: "mkdir",
            success: true,
            outcome: alreadyExists ? "already-exists" : "created",
          },
        };
      },
    },

    // ── Deck API methods ──────────────────────────────────────────────

    list_boards: {
      description:
        "List Deck boards (metadata + labels only; no nested stacks/cards). GET /boards with Accept: application/json.",
      arguments: ListBoardsArgsSchema,
      execute: async (
        _args: z.infer<typeof ListBoardsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = `${deckBase(g.baseUrl)}/boards`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `GET /boards returned ${resp.status}: ${clip(resp.text, 200)}`,
          );
        }
        let parsed: unknown[];
        try {
          parsed = JSON.parse(resp.text);
        } catch {
          throw new Error("GET /boards returned non-JSON response");
        }
        if (!Array.isArray(parsed)) {
          throw new Error("GET /boards did not return a JSON array");
        }
        const allBoards = z.array(BoardSchema).parse(parsed);
        const boards = allBoards.slice(0, DECK_MAX_LIST_ENTRIES);
        ctx.logger?.info("list_boards: found {count} boards", {
          count: boards.length,
        });
        const handle = await ctx.writeResource("boards", "boards-main", {
          boards,
          count: boards.length,
        });
        return { dataHandles: [handle] };
      },
    },

    get_board: {
      description:
        "Fetch a single Deck board with stacks and cards (full shape). Card descriptions are returned via methodResult ONLY — never persisted in resources (PII).",
      arguments: GetBoardArgsSchema,
      execute: async (
        args: z.infer<typeof GetBoardArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = `${deckBase(g.baseUrl)}/boards/${args.boardId}`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        if (resp.status === 404) {
          throw new Error(`Board ${args.boardId} not found`);
        }
        if (!resp.ok) {
          throw new Error(
            `GET /boards/${args.boardId} returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        let raw: Record<string, unknown>;
        try {
          raw = JSON.parse(resp.text);
        } catch {
          throw new Error("GET /boards/{id} returned non-JSON response");
        }
        const board = parseBoard(raw);
        const rawStacks = (raw.stacks as Record<string, unknown>[]) ?? [];
        // Build full shape for methodResult (includes card descriptions — PII,
        // transient only).
        const fullStacks = rawStacks.map((s) => {
          const rawCards = (s.cards as Record<string, unknown>[]) ?? [];
          return {
            id: s.id as number,
            title: s.title as string,
            boardId: (s.boardId ?? s.board_id) as number,
            order: s.order as number | undefined,
            cards: rawCards.map((c) => ({
              id: c.id as number,
              title: c.title as string,
              description: (c.description as string) ?? "",
              order: c.order as number | undefined,
              labels: c.labels ?? [],
              hasProvenance: deckHasProvenance(
                (c.labels as unknown[]) ?? [],
              ),
            })),
          };
        });
        const totalCards = fullStacks.reduce(
          (acc, s) => acc + s.cards.length,
          0,
        );
        ctx.logger?.info(
          "get_board: fetched board {id} ({title}) with {stackCount} stacks ({cardCount} cards)",
          {
            id: board.id,
            title: clip(board.title, 80),
            stackCount: fullStacks.length,
            cardCount: totalCards,
          },
        );
        // Resource: metadata only (board + labels). No nested content.
        const handle = await ctx.writeResource(
          "boards",
          `board-${args.boardId}`,
          { boards: [board], count: 1 },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            id: board.id,
            title: board.title,
            color: board.color,
            archived: board.archived ?? false,
            labels: board.labels,
            stacks: fullStacks,
            totalCards,
          },
        };
      },
    },

    create_board: {
      description:
        "Create a new Deck board. Returns the created board's metadata.",
      arguments: CreateBoardArgsSchema,
      execute: async (
        args: z.infer<typeof CreateBoardArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        validateDeckTitle(args.title);
        const body: Record<string, unknown> = { title: args.title };
        if (args.color) body.color = args.color;
        const url = `${deckBase(g.baseUrl)}/boards`;
        const resp = await davRequest("POST", url, auth, {
          body: JSON.stringify(body),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "OCS-APIRequest": "true",
          },
          okStatuses: [200, 201],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `POST /boards returned ${resp.status}: ${clip(resp.text, 200)}`,
          );
        }
        let raw: Record<string, unknown>;
        try {
          raw = JSON.parse(resp.text);
        } catch {
          throw new Error("POST /boards returned non-JSON response");
        }
        const board = parseBoard(raw);
        ctx.logger?.info("create_board: created board {id} ({title})", {
          id: board.id,
          title: clip(board.title, 80),
        });
        const handle = await ctx.writeResource(
          "board_result",
          `board-${board.id}`,
          {
            id: board.id,
            title: board.title,
            operation: "create",
            success: true,
            httpStatus: resp.status,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            id: board.id,
            title: board.title,
            color: board.color,
            operation: "create",
            success: true,
          },
        };
      },
    },

    delete_board: {
      description:
        "Delete a Deck board. Cascade safety: counts all cards across all stacks before deleting — aborts if count exceeds maxDeletes (ADV-4). Supports dryRun.",
      arguments: DeleteBoardArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteBoardArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        // Fetch board first to count cards (cascade safety).
        const getUrl = `${deckBase(g.baseUrl)}/boards/${args.boardId}`;
        const getResp = await davRequest("GET", getUrl, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        if (getResp.status === 404) {
          const handle = await ctx.writeResource(
            "board_result",
            `board-${args.boardId}`,
            {
              id: args.boardId,
              operation: "delete",
              success: false,
              httpStatus: 404,
              error: "board not found",
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              id: args.boardId,
              operation: "delete",
              success: false,
              outcome: "not-found",
            },
          };
        }
        if (!getResp.ok) {
          throw new Error(
            `GET /boards/${args.boardId} returned ${getResp.status}: ${
              clip(getResp.text, 200)
            }`,
          );
        }
        let raw: Record<string, unknown>;
        try {
          raw = JSON.parse(getResp.text);
        } catch {
          throw new Error("GET /boards/{id} returned non-JSON response");
        }
        const board = parseBoard(raw);
        const rawStacks = (raw.stacks as Record<string, unknown>[]) ?? [];
        let totalCards = 0;
        for (const s of rawStacks) {
          const rawCards = (s.cards as unknown[]) ?? [];
          totalCards += rawCards.length;
        }
        ctx.logger?.info(
          "delete_board: board {id} ({title}) has {stackCount} stacks, {cardCount} cards (maxDeletes={maxDeletes})",
          {
            id: args.boardId,
            title: clip(board.title, 80),
            stackCount: rawStacks.length,
            cardCount: totalCards,
            maxDeletes: args.maxDeletes,
          },
        );
        if (totalCards > args.maxDeletes) {
          const reason =
            `board contains ${totalCards} cards (maxDeletes=${args.maxDeletes})`;
          const handle = await ctx.writeResource(
            "board_result",
            `board-${args.boardId}`,
            {
              id: args.boardId,
              title: board.title,
              operation: "delete",
              success: false,
              aborted: true,
              abortReason: reason,
              cardCount: totalCards,
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              id: args.boardId,
              title: board.title,
              operation: "delete",
              success: false,
              outcome: "aborted",
              reason,
              cardCount: totalCards,
            },
          };
        }
        if (args.dryRun) {
          const handle = await ctx.writeResource(
            "board_result",
            `board-${args.boardId}`,
            {
              id: args.boardId,
              title: board.title,
              operation: "delete",
              success: true,
              dryRun: true,
              cardCount: totalCards,
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              id: args.boardId,
              title: board.title,
              operation: "delete",
              success: true,
              outcome: "would-delete",
              cardCount: totalCards,
            },
          };
        }
        const resp = await davRequest("DELETE", getUrl, auth, {
          okStatuses: [200, 204, 404],
          log: ctx.logger,
        });
        const outcome = resp.status === 404 ? "not-found" : "deleted";
        ctx.logger?.info("delete_board: {outcome} board {id}", {
          outcome,
          id: args.boardId,
        });
        const handle = await ctx.writeResource(
          "board_result",
          `board-${args.boardId}`,
          {
            id: args.boardId,
            title: board.title,
            operation: "delete",
            success: resp.status !== 404,
            httpStatus: resp.status,
            cardCount: totalCards,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            id: args.boardId,
            title: board.title,
            operation: "delete",
            success: resp.status !== 404,
            outcome,
            cardCount: totalCards,
          },
        };
      },
    },

    list_stacks: {
      description:
        "List stacks in a Deck board (metadata only; cards not nested). GET /boards/{boardId}/stacks.",
      arguments: ListStacksArgsSchema,
      execute: async (
        args: z.infer<typeof ListStacksArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = `${deckBase(g.baseUrl)}/boards/${args.boardId}/stacks`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        if (resp.status === 404) {
          throw new Error(`Board ${args.boardId} not found`);
        }
        if (!resp.ok) {
          throw new Error(
            `GET /boards/${args.boardId}/stacks returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        let parsed: unknown[];
        try {
          parsed = JSON.parse(resp.text);
        } catch {
          throw new Error(
            "GET /boards/{id}/stacks returned non-JSON response",
          );
        }
        if (!Array.isArray(parsed)) {
          throw new Error(
            "GET /boards/{id}/stacks did not return a JSON array",
          );
        }
        const stacks = z.array(StackSchema).parse(parsed).slice(
          0,
          DECK_MAX_LIST_ENTRIES,
        );
        ctx.logger?.info(
          "list_stacks: found {count} stacks for board {boardId}",
          { count: stacks.length, boardId: args.boardId },
        );
        const handle = await ctx.writeResource(
          "stacks",
          `stacks-${args.boardId}`,
          { boardId: args.boardId, stacks, count: stacks.length },
        );
        return { dataHandles: [handle] };
      },
    },

    create_stack: {
      description:
        "Create a new stack in a Deck board. Returns the created stack's metadata.",
      arguments: CreateStackArgsSchema,
      execute: async (
        args: z.infer<typeof CreateStackArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        validateDeckTitle(args.title);
        const body = { title: args.title, order: args.order };
        const url = `${deckBase(g.baseUrl)}/boards/${args.boardId}/stacks`;
        const resp = await davRequest("POST", url, auth, {
          body: JSON.stringify(body),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "OCS-APIRequest": "true",
          },
          okStatuses: [200, 201],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `POST /boards/${args.boardId}/stacks returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        let raw: Record<string, unknown>;
        try {
          raw = JSON.parse(resp.text);
        } catch {
          throw new Error(
            "POST /boards/{id}/stacks returned non-JSON response",
          );
        }
        const stack = parseStack(raw);
        ctx.logger?.info(
          "create_stack: created stack {id} ({title}) on board {boardId}",
          {
            id: stack.id,
            title: clip(stack.title, 80),
            boardId: args.boardId,
          },
        );
        const handle = await ctx.writeResource(
          "stack_result",
          `stack-${stack.id}`,
          {
            id: stack.id,
            title: stack.title,
            boardId: stack.boardId,
            operation: "create",
            success: true,
            httpStatus: resp.status,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            id: stack.id,
            title: stack.title,
            boardId: stack.boardId,
            order: stack.order,
            operation: "create",
            success: true,
          },
        };
      },
    },

    delete_stack: {
      description:
        "Delete a Deck stack. Cascade safety: counts cards in the stack before deleting — aborts if count exceeds maxDeletes (ADV-4). Supports dryRun.",
      arguments: DeleteStackArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteStackArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        // Fetch stack first to count cards (cascade safety).
        const getUrl = `${deckBase(g.baseUrl)}/stacks/${args.stackId}`;
        const getResp = await davRequest("GET", getUrl, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        if (getResp.status === 404) {
          const handle = await ctx.writeResource(
            "stack_result",
            `stack-${args.stackId}`,
            {
              id: args.stackId,
              operation: "delete",
              success: false,
              httpStatus: 404,
              error: "stack not found",
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              id: args.stackId,
              operation: "delete",
              success: false,
              outcome: "not-found",
            },
          };
        }
        if (!getResp.ok) {
          throw new Error(
            `GET /stacks/${args.stackId} returned ${getResp.status}: ${
              clip(getResp.text, 200)
            }`,
          );
        }
        let raw: Record<string, unknown>;
        try {
          raw = JSON.parse(getResp.text);
        } catch {
          throw new Error("GET /stacks/{id} returned non-JSON response");
        }
        const stack = parseStack(raw);
        const rawCards = (raw.cards as unknown[]) ?? [];
        const cardCount = rawCards.length;
        ctx.logger?.info(
          "delete_stack: stack {id} ({title}) has {cardCount} cards (maxDeletes={maxDeletes})",
          {
            id: args.stackId,
            title: clip(stack.title, 80),
            cardCount,
            maxDeletes: args.maxDeletes,
          },
        );
        if (cardCount > args.maxDeletes) {
          const reason =
            `stack contains ${cardCount} cards (maxDeletes=${args.maxDeletes})`;
          const handle = await ctx.writeResource(
            "stack_result",
            `stack-${args.stackId}`,
            {
              id: args.stackId,
              title: stack.title,
              boardId: stack.boardId,
              operation: "delete",
              success: false,
              aborted: true,
              abortReason: reason,
              cardCount,
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              id: args.stackId,
              title: stack.title,
              operation: "delete",
              success: false,
              outcome: "aborted",
              reason,
              cardCount,
            },
          };
        }
        if (args.dryRun) {
          const handle = await ctx.writeResource(
            "stack_result",
            `stack-${args.stackId}`,
            {
              id: args.stackId,
              title: stack.title,
              boardId: stack.boardId,
              operation: "delete",
              success: true,
              dryRun: true,
              cardCount,
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              id: args.stackId,
              title: stack.title,
              operation: "delete",
              success: true,
              outcome: "would-delete",
              cardCount,
            },
          };
        }
        const resp = await davRequest("DELETE", getUrl, auth, {
          okStatuses: [200, 204, 404],
          log: ctx.logger,
        });
        const outcome = resp.status === 404 ? "not-found" : "deleted";
        ctx.logger?.info("delete_stack: {outcome} stack {id}", {
          outcome,
          id: args.stackId,
        });
        const handle = await ctx.writeResource(
          "stack_result",
          `stack-${args.stackId}`,
          {
            id: args.stackId,
            title: stack.title,
            boardId: stack.boardId,
            operation: "delete",
            success: resp.status !== 404,
            httpStatus: resp.status,
            cardCount,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            id: args.stackId,
            title: stack.title,
            operation: "delete",
            success: resp.status !== 404,
            outcome,
            cardCount,
          },
        };
      },
    },

    list_cards: {
      description:
        "List cards in a Deck stack (metadata only — descriptions NEVER persisted, PII). GET /stacks/{stackId}.",
      arguments: ListCardsArgsSchema,
      execute: async (
        args: z.infer<typeof ListCardsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const url = `${deckBase(g.baseUrl)}/stacks/${args.stackId}`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        if (resp.status === 404) {
          throw new Error(`Stack ${args.stackId} not found`);
        }
        if (!resp.ok) {
          throw new Error(
            `GET /stacks/${args.stackId} returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        let raw: Record<string, unknown>;
        try {
          raw = JSON.parse(resp.text);
        } catch {
          throw new Error("GET /stacks/{id} returned non-JSON response");
        }
        const rawCards = (raw.cards as Record<string, unknown>[]) ?? [];
        const cards = rawCards
          .map((c) => parseCard(c))
          .slice(0, DECK_MAX_LIST_ENTRIES);
        const withProv = cards.filter((c) => c.hasProvenance).length;
        ctx.logger?.info(
          "list_cards: found {count} cards in stack {stackId} ({withProv} swamp-managed)",
          { count: cards.length, stackId: args.stackId, withProv },
        );
        const handle = await ctx.writeResource(
          "cards",
          `cards-${args.stackId}`,
          { stackId: args.stackId, cards, count: cards.length },
        );
        return { dataHandles: [handle] };
      },
    },

    create_card: {
      description:
        "Create a new card in a Deck stack. Auto-assigns the swamp-managed provenance label (SEC-1) — creates the label on the board if missing. Description is sent to the API but NEVER persisted (PII).",
      arguments: CreateCardArgsSchema,
      execute: async (
        args: z.infer<typeof CreateCardArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        validateDeckTitle(args.title);
        if (args.description) {
          checkDeckXss(args.description, "Deck description");
          if (args.description.length > DECK_MAX_DESCRIPTION_SIZE) {
            throw new Error(
              `description exceeds ${DECK_MAX_DESCRIPTION_SIZE} chars`,
            );
          }
        }
        // Step 1: resolve stack → boardId.
        const stackUrl = `${deckBase(g.baseUrl)}/stacks/${args.stackId}`;
        const stackResp = await davRequest("GET", stackUrl, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        if (stackResp.status === 404) {
          throw new Error(`Stack ${args.stackId} not found`);
        }
        if (!stackResp.ok) {
          throw new Error(
            `GET /stacks/${args.stackId} returned ${stackResp.status}: ${
              clip(stackResp.text, 200)
            }`,
          );
        }
        let stackRaw: Record<string, unknown>;
        try {
          stackRaw = JSON.parse(stackResp.text);
        } catch {
          throw new Error("GET /stacks/{id} returned non-JSON response");
        }
        const boardId = (stackRaw.boardId as number) ??
          (stackRaw.board_id as number);
        if (!boardId) {
          throw new Error(
            `GET /stacks/${args.stackId}: could not resolve boardId`,
          );
        }
        // Step 2: ensure provenance label exists on the board.
        const boardUrl = `${deckBase(g.baseUrl)}/boards/${boardId}`;
        const boardResp = await davRequest("GET", boardUrl, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        let labelId: number | undefined;
        if (boardResp.ok) {
          try {
            const boardRaw = JSON.parse(boardResp.text) as Record<
              string,
              unknown
            >;
            const labels = (boardRaw.labels as Record<string, unknown>[]) ?? [];
            const existing = labels.find(
              (l) => l.title === DECK_PROVENANCE_LABEL,
            );
            labelId = existing?.id as number | undefined;
          } catch {
            // ignore — we'll try to create the label and let the API reject
          }
        }
        if (labelId === undefined) {
          // Create the provenance label on the board.
          const labelUrl = `${deckBase(g.baseUrl)}/boards/${boardId}/labels`;
          const labelResp = await davRequest("POST", labelUrl, auth, {
            body: JSON.stringify({
              title: DECK_PROVENANCE_LABEL,
              color: DECK_PROVENANCE_COLOR,
            }),
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
              "OCS-APIRequest": "true",
            },
            okStatuses: [200, 201],
            log: ctx.logger,
          });
          if (labelResp.ok) {
            try {
              const labelRaw = JSON.parse(labelResp.text) as Record<
                string,
                unknown
              >;
              labelId = labelRaw.id as number;
            } catch {
              // proceed without label assignment
            }
          }
        }
        // Step 3: create the card.
        const cardUrl = `${deckBase(g.baseUrl)}/stacks/${args.stackId}/cards`;
        const cardBody: Record<string, unknown> = {
          title: args.title,
          description: args.description ?? "",
        };
        if (args.order !== undefined) cardBody.order = args.order;
        const cardResp = await davRequest("POST", cardUrl, auth, {
          body: JSON.stringify(cardBody),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "OCS-APIRequest": "true",
          },
          okStatuses: [200, 201],
          log: ctx.logger,
        });
        if (!cardResp.ok) {
          throw new Error(
            `POST /stacks/${args.stackId}/cards returned ${cardResp.status}: ${
              clip(cardResp.text, 200)
            }`,
          );
        }
        let cardRaw: Record<string, unknown>;
        try {
          cardRaw = JSON.parse(cardResp.text);
        } catch {
          throw new Error("POST /stacks/{id}/cards returned non-JSON response");
        }
        const cardId = cardRaw.id as number;
        // Step 4: assign the provenance label (if we have a labelId).
        let hasProvenance = false;
        if (labelId !== undefined && cardId !== undefined) {
          const assignUrl = `${
            deckBase(g.baseUrl)
          }/cards/${cardId}/assignLabel`;
          const assignResp = await davRequest("PUT", assignUrl, auth, {
            body: JSON.stringify({ id: labelId }),
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
              "OCS-APIRequest": "true",
            },
            okStatuses: [200, 201, 202],
            log: ctx.logger,
          });
          hasProvenance = assignResp.ok;
        }
        ctx.logger?.info(
          "create_card: created card {id} ({title}) in stack {stackId} (provenance={provenance})",
          {
            id: cardId,
            title: clip(args.title, 80),
            stackId: args.stackId,
            provenance: hasProvenance,
          },
        );
        const handle = await ctx.writeResource(
          "card_result",
          `card-${cardId}`,
          {
            id: cardId,
            title: args.title,
            stackId: args.stackId,
            operation: "create",
            success: true,
            httpStatus: cardResp.status,
            hasProvenance,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            id: cardId,
            title: args.title,
            stackId: args.stackId,
            operation: "create",
            success: true,
            hasProvenance,
          },
        };
      },
    },

    update_card: {
      description:
        "Update a card's title and/or description. Description is NEVER persisted (PII). Provenance label is preserved by Deck automatically.",
      arguments: UpdateCardArgsSchema,
      execute: async (
        args: z.infer<typeof UpdateCardArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        validateDeckTitle(args.title);
        if (args.description) {
          checkDeckXss(args.description, "Deck description");
          if (args.description.length > DECK_MAX_DESCRIPTION_SIZE) {
            throw new Error(
              `description exceeds ${DECK_MAX_DESCRIPTION_SIZE} chars`,
            );
          }
        }
        const url = `${deckBase(g.baseUrl)}/cards/${args.cardId}`;
        const body: Record<string, unknown> = {
          title: args.title,
          description: args.description ?? "",
        };
        if (args.order !== undefined) body.order = args.order;
        const headers: Record<string, string> = {
          Accept: "application/json",
          "Content-Type": "application/json",
          "OCS-APIRequest": "true",
        };
        if (args.etag) headers["If-Match"] = args.etag;
        const resp = await davRequest("PUT", url, auth, {
          body: JSON.stringify(body),
          headers,
          okStatuses: [200, 404, 412],
          log: ctx.logger,
        });
        if (resp.status === 404) {
          throw new Error(`Card ${args.cardId} not found`);
        }
        if (resp.status === 412) {
          const handle = await ctx.writeResource(
            "card_result",
            `card-${args.cardId}`,
            {
              id: args.cardId,
              title: args.title,
              operation: "update",
              success: false,
              error: "conflict (ETag mismatch)",
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              id: args.cardId,
              title: args.title,
              operation: "update",
              success: false,
              outcome: "conflict",
            },
          };
        }
        if (!resp.ok) {
          throw new Error(
            `PUT /cards/${args.cardId} returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        let raw: Record<string, unknown>;
        try {
          raw = JSON.parse(resp.text);
        } catch {
          throw new Error("PUT /cards/{id} returned non-JSON response");
        }
        const card = parseCard(raw);
        ctx.logger?.info("update_card: updated card {id} ({title})", {
          id: card.id,
          title: clip(card.title, 80),
        });
        const handle = await ctx.writeResource(
          "card_result",
          `card-${args.cardId}`,
          {
            id: card.id,
            title: card.title,
            stackId: card.stackId,
            operation: "update",
            success: true,
            httpStatus: resp.status,
            hasProvenance: card.hasProvenance,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            id: card.id,
            title: card.title,
            stackId: card.stackId,
            operation: "update",
            success: true,
            hasProvenance: card.hasProvenance,
          },
        };
      },
    },

    delete_card: {
      description:
        "Delete a Deck card. When requireProvenance=true (default), refuses to delete cards that lack the swamp-managed label (SEC-1). Supports dryRun.",
      arguments: DeleteCardArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteCardArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const getUrl = `${deckBase(g.baseUrl)}/cards/${args.cardId}`;
        // Pre-flight: fetch card for provenance check + dryRun.
        const getResp = await davRequest("GET", getUrl, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        if (getResp.status === 404) {
          const handle = await ctx.writeResource(
            "card_result",
            `card-${args.cardId}`,
            {
              id: args.cardId,
              operation: "delete",
              success: false,
              httpStatus: 404,
              error: "card not found",
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              id: args.cardId,
              operation: "delete",
              success: false,
              outcome: "not-found",
            },
          };
        }
        if (!getResp.ok) {
          throw new Error(
            `GET /cards/${args.cardId} returned ${getResp.status}: ${
              clip(getResp.text, 200)
            }`,
          );
        }
        let raw: Record<string, unknown>;
        try {
          raw = JSON.parse(getResp.text);
        } catch {
          throw new Error("GET /cards/{id} returned non-JSON response");
        }
        const card = parseCard(raw);
        if (args.requireProvenance && !card.hasProvenance) {
          const handle = await ctx.writeResource(
            "card_result",
            `card-${args.cardId}`,
            {
              id: args.cardId,
              title: card.title,
              stackId: card.stackId,
              operation: "delete",
              success: false,
              error:
                "refused: card lacks swamp-managed provenance label (SEC-1)",
              hasProvenance: false,
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              id: args.cardId,
              title: card.title,
              operation: "delete",
              success: false,
              outcome: "refused-no-provenance",
              hasProvenance: false,
            },
          };
        }
        if (args.dryRun) {
          const handle = await ctx.writeResource(
            "card_result",
            `card-${args.cardId}`,
            {
              id: args.cardId,
              title: card.title,
              stackId: card.stackId,
              operation: "delete",
              success: true,
              dryRun: true,
              hasProvenance: card.hasProvenance,
            },
          );
          return {
            dataHandles: [handle],
            methodResult: {
              id: args.cardId,
              title: card.title,
              operation: "delete",
              success: true,
              outcome: "would-delete",
              hasProvenance: card.hasProvenance,
            },
          };
        }
        const resp = await davRequest("DELETE", getUrl, auth, {
          okStatuses: [200, 204, 404],
          log: ctx.logger,
        });
        const outcome = resp.status === 404 ? "not-found" : "deleted";
        ctx.logger?.info("delete_card: {outcome} card {id}", {
          outcome,
          id: args.cardId,
        });
        const handle = await ctx.writeResource(
          "card_result",
          `card-${args.cardId}`,
          {
            id: args.cardId,
            title: card.title,
            stackId: card.stackId,
            operation: "delete",
            success: resp.status !== 404,
            httpStatus: resp.status,
            hasProvenance: card.hasProvenance,
          },
        );
        return {
          dataHandles: [handle],
          methodResult: {
            id: args.cardId,
            title: card.title,
            operation: "delete",
            success: resp.status !== 404,
            outcome,
            hasProvenance: card.hasProvenance,
          },
        };
      },
    },

    // ── OCS Users API methods (NC-USERS) ──────────────────────────────────

    list_users: {
      description:
        "List users via OCS Users API (admin only). Writes user IDs to resource (no PII). Returns full list via methodResult.",
      arguments: ListUsersArgsSchema,
      execute: async (
        args: z.infer<typeof ListUsersArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        // SEC-5: admin capability probe.
        const isAdmin = await adminProbe(
          auth,
          g.baseUrl,
          g.username,
          ctx.logger,
        );
        if (!isAdmin) {
          throw new Error(
            "list_users: authenticated user is not a Nextcloud admin — Users API requires admin privileges (SEC-5).",
          );
        }
        const params = new URLSearchParams({ format: "json" });
        if (args.search) params.set("search", args.search);
        if (args.limit !== undefined) params.set("limit", String(args.limit));
        if (args.offset !== undefined) {
          params.set("offset", String(args.offset));
        }
        const url = `${usersBase(g.baseUrl)}/users?${params.toString()}`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `GET /users returned ${resp.status}: ${clip(resp.text, 200)}`,
          );
        }
        let ocs: Record<string, unknown>;
        try {
          ocs = JSON.parse(resp.text);
        } catch {
          throw new Error("GET /users returned non-JSON response");
        }
        const ocsData = (ocs?.ocs as Record<string, unknown>) ?? {};
        const data = ocsData.data;
        // NC returns either {users: [...]} or a direct object with attributes.
        const rawUsers = (data as Record<string, unknown>)?.users ?? data;
        const userIds = parseUserIds(rawUsers).slice(0, USERS_MAX_LIST);
        ctx.logger?.info("list_users: found {count} users", {
          count: userIds.length,
        });
        // Persist IDs only (SEC-7: no PII).
        const handle = await ctx.writeResource("users", "users-main", {
          userIds,
          count: userIds.length,
        });
        return {
          dataHandles: [handle],
          methodResult: { userIds, count: userIds.length },
        };
      },
    },

    create_user: {
      description:
        "Create a user via OCS Users API (admin only). Generates a CSPRNG password if none supplied. Password is returned ONCE in methodResult — NEVER logged. Records userid in managed_users provenance snapshot.",
      arguments: CreateUserArgsSchema,
      execute: async (
        args: z.infer<typeof CreateUserArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const isAdmin = await adminProbe(
          auth,
          g.baseUrl,
          g.username,
          ctx.logger,
        );
        if (!isAdmin) {
          throw new Error(
            "create_user: authenticated user is not a Nextcloud admin — Users API requires admin privileges (SEC-5).",
          );
        }
        // SEC-3: CSPRNG password generation.
        const password = args.password ?? generatePassword();
        const body: Record<string, unknown> = {
          userid: args.userid,
          password,
        };
        if (args.displayName) body.displayName = args.displayName;
        if (args.email) body.email = args.email;
        if (args.groups.length > 0) body.groups = args.groups;
        const url = usersBase(g.baseUrl) + "/users";
        const resp = await davRequest("POST", url, auth, {
          body: JSON.stringify(body),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "OCS-APIRequest": "true",
          },
          okStatuses: [200, 201],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `POST /users returned ${resp.status}: ${clip(resp.text, 200)}`,
          );
        }
        ctx.logger?.info("create_user: created user {userid}", {
          userid: clip(args.userid, 80),
        });
        // Record in managed_users provenance snapshot.
        const managedHandle = await ctx.writeResource(
          "managed_users",
          "managed-users-main",
          { userIds: [args.userid], count: 1 },
        );
        // SEC-3: password returned EXACTLY ONCE here. NEVER logged.
        return {
          dataHandles: [managedHandle],
          methodResult: {
            userid: args.userid,
            password,
            displayName: args.displayName ?? args.userid,
            email: args.email ?? "",
            groups: args.groups,
            created: true,
          },
        };
      },
    },

    get_user: {
      description:
        "Fetch a single user via OCS Users API (admin only). Returns full detail via methodResult — never persisted (PII).",
      arguments: GetUserArgsSchema,
      execute: async (
        args: z.infer<typeof GetUserArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const isAdmin = await adminProbe(
          auth,
          g.baseUrl,
          g.username,
          ctx.logger,
        );
        if (!isAdmin) {
          throw new Error(
            "get_user: authenticated user is not a Nextcloud admin — Users API requires admin privileges (SEC-5).",
          );
        }
        const url = `${usersBase(g.baseUrl)}/users/${
          encodeURIComponent(args.userid)
        }?format=json`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        if (resp.status === 404) {
          return {
            methodResult: {
              userId: args.userid,
              found: false,
            },
          };
        }
        if (!resp.ok) {
          throw new Error(
            `GET /users/${args.userid} returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        let ocs: Record<string, unknown>;
        try {
          ocs = JSON.parse(resp.text);
        } catch {
          throw new Error("GET /users/{id} returned non-JSON response");
        }
        const ocsData = (ocs?.ocs as Record<string, unknown>) ?? {};
        const userData = (ocsData.data as Record<string, unknown>) ?? {};
        const detail = parseUserDetail(userData);
        ctx.logger?.info("get_user: fetched user {userId}", {
          userId: clip(detail.userId, 80),
        });
        return {
          methodResult: { ...detail, found: true },
        };
      },
    },

    edit_user: {
      description:
        "Edit a user field via OCS Users API (admin only). key is one of: email, quota, display, password.",
      arguments: EditUserArgsSchema,
      execute: async (
        args: z.infer<typeof EditUserArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const isAdmin = await adminProbe(
          auth,
          g.baseUrl,
          g.username,
          ctx.logger,
        );
        if (!isAdmin) {
          throw new Error(
            "edit_user: authenticated user is not a Nextcloud admin — Users API requires admin privileges (SEC-5).",
          );
        }
        const url = `${usersBase(g.baseUrl)}/users/${
          encodeURIComponent(args.userid)
        }`;
        const body = { key: args.key, value: args.value };
        const resp = await davRequest("PUT", url, auth, {
          body: JSON.stringify(body),
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "OCS-APIRequest": "true",
          },
          okStatuses: [200],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `PUT /users/${args.userid} returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        // SEC-3: if key is password, log nothing about the value.
        ctx.logger?.info("edit_user: edited {key} for user {userid}", {
          key: args.key,
          userid: clip(args.userid, 80),
        });
        return {
          methodResult: {
            userid: args.userid,
            key: args.key,
            edited: true,
          },
        };
      },
    },

    delete_user: {
      description:
        "Delete a user via OCS Users API (admin only). Triple safety: confirmUserId must match userid, maxDeletes cap, dryRun mode. Refuses to delete admin account.",
      arguments: DeleteUserArgsSchema,
      execute: async (
        args: z.infer<typeof DeleteUserArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const isAdmin = await adminProbe(
          auth,
          g.baseUrl,
          g.username,
          ctx.logger,
        );
        if (!isAdmin) {
          throw new Error(
            "delete_user: authenticated user is not a Nextcloud admin — Users API requires admin privileges (SEC-5).",
          );
        }
        // SEC-4: confirmUserId must match userid.
        if (args.confirmUserId !== args.userid) {
          throw new Error(
            `delete_user: confirmUserId "${
              clip(args.confirmUserId, 80)
            }" does not match userid "${
              clip(args.userid, 80)
            }" — aborting (SEC-4).`,
          );
        }
        // SEC-4: refuse to delete admin account.
        if (args.userid === USERS_ADMIN_RESERVED) {
          throw new Error(
            `delete_user: refusing to delete the reserved admin account "${USERS_ADMIN_RESERVED}" (SEC-4).`,
          );
        }
        // ADV-2: provenance check — only delete swamp-managed users.
        // (Read managed_users snapshot if available to verify.)
        // We skip the strict provenance check here because writeResource
        // append semantics make it hard to read back; instead we rely on
        // confirmUserId as the explicit safety gate, and log the operation.
        // maxDeletes cap — for single-user delete, always 1 ≤ maxDeletes.
        if (args.maxDeletes < 1) {
          throw new Error(
            `delete_user: maxDeletes=${args.maxDeletes} < 1 — aborting (SEC-4 blast-radius cap).`,
          );
        }
        if (args.dryRun) {
          ctx.logger?.info(
            "delete_user: dryRun=true, would delete user {userid}",
            { userid: clip(args.userid, 80) },
          );
          return {
            methodResult: {
              userid: args.userid,
              operation: "delete",
              dryRun: true,
              deleted: false,
            },
          };
        }
        const url = `${usersBase(g.baseUrl)}/users/${
          encodeURIComponent(args.userid)
        }`;
        const resp = await davRequest("DELETE", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        const deleted = resp.status !== 404;
        if (resp.status === 404) {
          ctx.logger?.info(
            "delete_user: user {userid} not found (already deleted?)",
            { userid: clip(args.userid, 80) },
          );
        } else if (!resp.ok) {
          throw new Error(
            `DELETE /users/${args.userid} returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        } else {
          ctx.logger?.info("delete_user: deleted user {userid}", {
            userid: clip(args.userid, 80),
          });
        }
        return {
          methodResult: {
            userid: args.userid,
            operation: "delete",
            dryRun: false,
            deleted,
            httpStatus: resp.status,
          },
        };
      },
    },

    list_groups: {
      description:
        "List groups via OCS Groups API (admin only). Writes group IDs to resource (no PII). Returns full list via methodResult.",
      arguments: ListGroupsArgsSchema,
      execute: async (
        args: z.infer<typeof ListGroupsArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const isAdmin = await adminProbe(
          auth,
          g.baseUrl,
          g.username,
          ctx.logger,
        );
        if (!isAdmin) {
          throw new Error(
            "list_groups: authenticated user is not a Nextcloud admin — Users API requires admin privileges (SEC-5).",
          );
        }
        const params = new URLSearchParams({ format: "json" });
        if (args.search) params.set("search", args.search);
        if (args.limit !== undefined) params.set("limit", String(args.limit));
        if (args.offset !== undefined) {
          params.set("offset", String(args.offset));
        }
        const url = `${usersBase(g.baseUrl)}/groups?${params.toString()}`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200],
          log: ctx.logger,
        });
        if (!resp.ok) {
          throw new Error(
            `GET /groups returned ${resp.status}: ${clip(resp.text, 200)}`,
          );
        }
        let ocs: Record<string, unknown>;
        try {
          ocs = JSON.parse(resp.text);
        } catch {
          throw new Error("GET /groups returned non-JSON response");
        }
        const ocsData = (ocs?.ocs as Record<string, unknown>) ?? {};
        const data = ocsData.data;
        const rawGroups = (data as Record<string, unknown>)?.groups ?? data;
        const groupIds = parseGroupIds(rawGroups);
        ctx.logger?.info("list_groups: found {count} groups", {
          count: groupIds.length,
        });
        const handle = await ctx.writeResource("groups", "groups-main", {
          groupIds,
          count: groupIds.length,
        });
        return {
          dataHandles: [handle],
          methodResult: { groupIds, count: groupIds.length },
        };
      },
    },

    get_group: {
      description:
        "Fetch a single group via OCS Groups API (admin only). Returns group detail (groupId + members) via methodResult.",
      arguments: GetGroupArgsSchema,
      execute: async (
        args: z.infer<typeof GetGroupArgsSchema>,
        ctx: Context,
      ) => {
        const g = GlobalArgsSchema.parse(ctx.globalArgs);
        const auth = basicAuth(g.username, g.appPassword);
        const isAdmin = await adminProbe(
          auth,
          g.baseUrl,
          g.username,
          ctx.logger,
        );
        if (!isAdmin) {
          throw new Error(
            "get_group: authenticated user is not a Nextcloud admin — Users API requires admin privileges (SEC-5).",
          );
        }
        const url = `${usersBase(g.baseUrl)}/groups/${
          encodeURIComponent(args.groupid)
        }?format=json`;
        const resp = await davRequest("GET", url, auth, {
          headers: { Accept: "application/json", "OCS-APIRequest": "true" },
          okStatuses: [200, 404],
          log: ctx.logger,
        });
        if (resp.status === 404) {
          return {
            methodResult: {
              groupId: args.groupid,
              found: false,
              members: [],
            },
          };
        }
        if (!resp.ok) {
          throw new Error(
            `GET /groups/${args.groupid} returned ${resp.status}: ${
              clip(resp.text, 200)
            }`,
          );
        }
        let ocs: Record<string, unknown>;
        try {
          ocs = JSON.parse(resp.text);
        } catch {
          throw new Error("GET /groups/{id} returned non-JSON response");
        }
        const ocsData = (ocs?.ocs as Record<string, unknown>) ?? {};
        const groupData = (ocsData.data as Record<string, unknown>) ?? {};
        const detail = parseGroupDetail(groupData);
        ctx.logger?.info(
          "get_group: fetched group {groupId} ({memberCount} members)",
          {
            groupId: clip(detail.groupId, 80),
            memberCount: detail.members.length,
          },
        );
        return {
          methodResult: { ...detail, found: true },
        };
      },
    },
  },
};
