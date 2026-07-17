import { z } from "npm:zod@4";

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
    .min(1)
    .describe("Events to upsert (fan-out: one dispatch handles all)."),
});

const DeleteEventsArgsSchema = z.object({
  calendar: z.string().min(1).describe("Target calendar name."),
  uids: z
    .array(z.string().min(1))
    .min(1)
    .describe("iCalUIDs to delete (fan-out)."),
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
  outcome: z.enum(["deleted", "not-found", "failed"]),
  httpStatus: z.number(),
  error: z.string().optional(),
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

type DavResponse = { status: number; ok: boolean; text: string };

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
  return { status: resp.status, ok: resp.ok, text };
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

/**
 * Render a DTSTART/DTEND line.
 * - all-day (`date`) → `;VALUE=DATE:YYYYMMDD`
 * - timed with explicit offset/Z → normalized to UTC `YYYYMMDDTHHMMSSZ`
 *   (deterministic, no VTIMEZONE needed)
 * - timed floating (no offset) with `timeZone` → `;TZID=<tz>:YYYYMMDDTHHMMSS`
 *   (host-independent; Nextcloud resolves IANA TZIDs)
 * - timed floating with no `timeZone` → throws (would be host-timezone dependent)
 */
export function renderDtLine(
  prop: "DTSTART" | "DTEND",
  t: z.infer<typeof EventTimeSchema>,
): string {
  if (t.date) return `${prop};VALUE=DATE:${compactDate(t.date)}`;
  if (t.dateTime) {
    if (hasZone(t.dateTime)) {
      const d = new Date(t.dateTime);
      if (isNaN(d.getTime())) {
        throw new Error(`Invalid ${prop} dateTime: ${clip(t.dateTime, 40)}`);
      }
      return `${prop}:${utcStamp(d)}`;
    }
    if (t.timeZone) {
      const tz = t.timeZone.replace(/[^A-Za-z0-9_+\-\/]/g, "");
      return `${prop};TZID=${tz}:${compactLocal(t.dateTime)}`;
    }
    throw new Error(
      `${prop} dateTime has no UTC offset and no timeZone; cannot resolve a deterministic instant`,
    );
  }
  throw new Error(`${prop} requires either date or dateTime`);
}

/**
 * Build a full VCALENDAR wrapping a single VEVENT for the given event. Every
 * emitted field is escaped or digit/enum-constrained, so no caller value can
 * inject an iCal property or component even if schema validation is bypassed.
 * `now` is injected for deterministic testing (DTSTAMP).
 */
export function buildVcalendar(ev: EventInput, now: Date = new Date()): string {
  const lines: string[] = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//kneel//swamp-nextcloud//EN",
    "CALSCALE:GREGORIAN",
    "BEGIN:VEVENT",
    `UID:${escapeText(ev.uid)}`,
    `DTSTAMP:${utcStamp(now)}`,
    renderDtLine("DTSTART", ev.start),
    renderDtLine("DTEND", ev.end),
    `SEQUENCE:${ev.sequence ?? 0}`,
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
// Model definition
// ---------------------------------------------------------------------------

export const model = {
  type: "@kneel/nextcloud",
  version: "2026.07.17.1",
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
        deleted: z.number(),
        failed: z.number(),
        results: z.array(DeleteOutcomeSchema),
      }),
      lifetime: "1d" as const,
      garbageCollection: 7,
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
        const handle = await ctx.writeResource("upsert", args.calendar, {
          calendar: args.calendar,
          upserted: results.length - failed,
          failed,
          results,
        });
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

        for (const uid of args.uids) {
          const href = eventHref(g.baseUrl, g.username, args.calendar, uid);
          try {
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
        ctx.logger?.info(
          "Deleted {deleted} events from {calendar} ({failed} failed)",
          { deleted, calendar: args.calendar, failed },
        );
        const handle = await ctx.writeResource("deletions", args.calendar, {
          calendar: args.calendar,
          deleted,
          failed,
          results,
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
