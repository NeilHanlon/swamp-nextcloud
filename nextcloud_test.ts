import { assert, assertEquals, assertThrows } from "jsr:@std/assert@1";
import {
  basicAuth,
  buildVcalendar,
  calendarUrl,
  clip,
  compactDate,
  davBase,
  escapeText,
  EventInputSchema,
  eventHref,
  extractAll,
  extractFirst,
  fnv1a,
  foldLine,
  GlobalArgsSchema,
  hasControlChars,
  hasElement,
  hasZone,
  ocsBase,
  octetLength,
  parseCalendars,
  renderDtLine,
  safePath,
  utcStamp,
} from "./nextcloud.ts";

// ── auth + URL construction ────────────────────────────────────────────────

Deno.test("basicAuth encodes user:pass as base64", () => {
  // btoa("alice:s3cr3t") === "YWxpY2U6czNjcjN0"
  assertEquals(basicAuth("alice", "s3cr3t"), "Basic YWxpY2U6czNjcjN0");
});

Deno.test("davBase / ocsBase strip trailing slash", () => {
  assertEquals(
    davBase("https://cloud.example.com/"),
    "https://cloud.example.com/remote.php/dav",
  );
  assertEquals(
    ocsBase("https://cloud.example.com"),
    "https://cloud.example.com/ocs/v2.php",
  );
});

Deno.test("calendarUrl encodes user + calendar and trims slashes", () => {
  assertEquals(
    calendarUrl("https://cloud.example.com", "alice", "/personal/"),
    "https://cloud.example.com/remote.php/dav/calendars/alice/personal/",
  );
});

// ── event href / hashing ───────────────────────────────────────────────────

Deno.test("fnv1a is deterministic and 8 hex chars", () => {
  assertEquals(fnv1a("abc"), fnv1a("abc"));
  assert(/^[0-9a-f]{8}$/.test(fnv1a("some-uid@google.com")));
  assert(fnv1a("a@b") !== fnv1a("a_b"), "distinct inputs → distinct hashes");
});

Deno.test("eventHref is stable per UID and filesystem-safe", () => {
  const a = eventHref("https://cloud.example.com", "alice", "personal", "x/y@z.com");
  const b = eventHref("https://cloud.example.com", "alice", "personal", "x/y@z.com");
  assertEquals(a, b, "same UID → same href (idempotent upsert)");
  assert(a.endsWith(".ics"));
  const name = a.split("/").pop()!;
  assert(/^[A-Za-z0-9._-]+\.ics$/.test(name), `unsafe name: ${name}`);
});

Deno.test("safePath drops query and userinfo", () => {
  assertEquals(
    safePath("https://cloud.example.com/ocs/v2.php/cloud/user?format=json"),
    "https://cloud.example.com/ocs/v2.php/cloud/user",
  );
});

// ── iCalendar TEXT escaping + folding ───────────────────────────────────────

Deno.test("escapeText escapes RFC5545 specials", () => {
  assertEquals(
    escapeText("a; b, c\\d\ne"),
    "a\\; b\\, c\\\\d\\ne",
  );
});

Deno.test("foldLine wraps at 75 octets with CRLF + space", () => {
  const long = "X".repeat(200);
  const folded = foldLine(long);
  assert(folded.includes("\r\n "));
  for (const seg of folded.split("\r\n")) {
    assert(seg.length <= 75, `segment too long: ${seg.length}`);
  }
});

Deno.test("foldLine leaves short lines untouched", () => {
  assertEquals(foldLine("SUMMARY:hi"), "SUMMARY:hi");
});

// ── date/time rendering ─────────────────────────────────────────────────────

Deno.test("utcStamp renders compact Zulu", () => {
  assertEquals(utcStamp(new Date("2026-07-17T18:30:05.000Z")), "20260717T183005Z");
});

Deno.test("compactDate strips dashes", () => {
  assertEquals(compactDate("2026-07-17"), "20260717");
});

Deno.test("renderDtLine handles all-day and timed", () => {
  assertEquals(renderDtLine("DTSTART", { date: "2026-07-17" }), "DTSTART;VALUE=DATE:20260717");
  assertEquals(
    renderDtLine("DTEND", { dateTime: "2026-07-17T14:00:00-04:00" }),
    "DTEND:20260717T180000Z",
  );
});

Deno.test("renderDtLine rejects empty and invalid times", () => {
  assertThrows(() => renderDtLine("DTSTART", {}));
  assertThrows(() => renderDtLine("DTSTART", { dateTime: "not-a-date" }));
});

// ── VCALENDAR construction ──────────────────────────────────────────────────

Deno.test("buildVcalendar emits a well-formed timed VEVENT", () => {
  const ics = buildVcalendar(
    {
      uid: "evt-1@google.com",
      summary: "Standup; daily",
      description: "line1\nline2",
      location: "Room 3",
      start: { dateTime: "2026-07-17T09:00:00Z" },
      end: { dateTime: "2026-07-17T09:30:00Z" },
      status: "confirmed",
      recurrence: ["RRULE:FREQ=WEEKLY;BYDAY=MO"],
    },
    new Date("2026-07-17T00:00:00Z"),
  );
  assert(ics.startsWith("BEGIN:VCALENDAR\r\n"));
  assert(ics.trimEnd().endsWith("END:VCALENDAR"));
  assert(ics.includes("UID:evt-1@google.com\r\n"));
  assert(ics.includes("DTSTAMP:20260717T000000Z\r\n"));
  assert(ics.includes("DTSTART:20260717T090000Z\r\n"));
  assert(ics.includes("DTEND:20260717T093000Z\r\n"));
  assert(ics.includes("SUMMARY:Standup\\; daily\r\n"));
  assert(ics.includes("DESCRIPTION:line1\\nline2\r\n"));
  assert(ics.includes("STATUS:CONFIRMED\r\n"));
  assert(ics.includes("RRULE:FREQ=WEEKLY;BYDAY=MO\r\n"));
});

Deno.test("buildVcalendar emits all-day VEVENT and cancelled status", () => {
  const ics = buildVcalendar({
    uid: "holiday-1",
    summary: "Holiday",
    start: { date: "2026-12-25" },
    end: { date: "2026-12-26" },
    status: "cancelled",
  }, new Date("2026-07-17T00:00:00Z"));
  assert(ics.includes("DTSTART;VALUE=DATE:20261225\r\n"));
  assert(ics.includes("DTEND;VALUE=DATE:20261226\r\n"));
  assert(ics.includes("STATUS:CANCELLED\r\n"));
});

// ── PROPFIND XML parsing ────────────────────────────────────────────────────

const PROPFIND_FIXTURE = `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav"
               xmlns:cs="http://calendarserver.org/ns/" xmlns:ic="http://apple.com/ns/ical/">
  <d:response>
    <d:href>/remote.php/dav/calendars/alice/personal/</d:href>
    <d:propstat><d:prop>
      <d:displayname>Personal</d:displayname>
      <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
      <ic:calendar-color>#0082c9</ic:calendar-color>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/calendars/alice/gcal-sub/</d:href>
    <d:propstat><d:prop>
      <d:displayname>Google (subscribed)</d:displayname>
      <d:resourcetype><d:collection/><cs:subscribed/></d:resourcetype>
      <cs:source><d:href>https://calendar.google.com/SECRET/basic.ics</d:href></cs:source>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/calendars/alice/</d:href>
    <d:propstat><d:prop>
      <d:displayname>alice</d:displayname>
      <d:resourcetype><d:collection/></d:resourcetype>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
</d:multistatus>`;

Deno.test("extractAll / extractFirst pull namespaced elements", () => {
  const responses = extractAll(PROPFIND_FIXTURE, "response");
  assertEquals(responses.length, 3);
  assertEquals(extractFirst(responses[0], "displayname"), "Personal");
});

Deno.test("hasElement detects self-closing namespaced tags", () => {
  assert(hasElement("<d:collection/><cs:subscribed/>", "subscribed"));
  assert(!hasElement("<d:collection/><cal:calendar/>", "subscribed"));
});

Deno.test("parseCalendars keeps calendars, masks subscription source, drops plain collections", () => {
  const cals = parseCalendars(PROPFIND_FIXTURE);
  // The bare principal collection (no <calendar>/<subscribed>) is excluded.
  assertEquals(cals.length, 2);

  const personal = cals.find((c) => c.displayName === "Personal")!;
  assertEquals(personal.path, "/remote.php/dav/calendars/alice/personal/");
  assertEquals(personal.color, "#0082c9");
  assertEquals(personal.hasSource, false);

  const sub = cals.find((c) => c.displayName === "Google (subscribed)")!;
  assertEquals(sub.hasSource, true);
});

Deno.test("parseCalendars NEVER leaks the secret source URL", () => {
  const serialized = JSON.stringify(parseCalendars(PROPFIND_FIXTURE));
  assert(
    !serialized.includes("SECRET") && !serialized.includes("calendar.google.com"),
    "subscription source URL must not appear in the parsed result",
  );
});

// A hostile server that smuggles the secret <source> URL INSIDE <displayname>
// (SEC-4). sanitizeXmlText must drop the nested element and its text content.
const HOSTILE_FIXTURE = `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response>
    <d:href>/remote.php/dav/calendars/alice/evil/</d:href>
    <d:propstat><d:prop>
      <d:displayname>Innocent<cal:source><d:href>https://calendar.google.com/LEAK/basic.ics</d:href></cal:source></d:displayname>
      <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>`;

Deno.test("parseCalendars masks a source URL smuggled inside displayname", () => {
  const cals = parseCalendars(HOSTILE_FIXTURE);
  assertEquals(cals.length, 1);
  assertEquals(cals[0].displayName, "Innocent");
  const serialized = JSON.stringify(cals);
  assert(
    !serialized.includes("LEAK") && !serialized.includes("calendar.google.com"),
    "nested source URL must not survive into the displayName",
  );
});

// ── security: https enforcement + iCal injection rejection ──────────────────

Deno.test("GlobalArgsSchema rejects http:// baseUrl (Basic auth is TLS-only)", () => {
  assert(
    !GlobalArgsSchema.safeParse({
      baseUrl: "http://cloud.example.com",
      username: "alice",
      appPassword: "x",
    }).success,
  );
  assert(
    GlobalArgsSchema.safeParse({
      baseUrl: "https://cloud.example.com",
      username: "alice",
      appPassword: "x",
    }).success,
  );
});

Deno.test("hasControlChars detects CR/LF and friends", () => {
  assert(hasControlChars("a\r\nb"));
  assert(hasControlChars("a\tb"));
  assert(!hasControlChars("plain text 123"));
});

Deno.test("EventInputSchema rejects CRLF injection via recurrence (SEC-1)", () => {
  const bad = EventInputSchema.safeParse({
    uid: "e1",
    start: { dateTime: "2026-07-17T09:00:00Z" },
    end: { dateTime: "2026-07-17T09:30:00Z" },
    recurrence: ["RRULE:FREQ=WEEKLY\r\nATTENDEE:mailto:evil@example.com"],
  });
  assert(!bad.success, "recurrence with embedded CRLF must be rejected");
});

Deno.test("EventInputSchema rejects a bad all-day date (SEC-2)", () => {
  const bad = EventInputSchema.safeParse({
    uid: "e2",
    start: { date: "2026-01-01\r\nX-EVIL:pwned" },
    end: { date: "2026-01-02" },
  });
  assert(!bad.success, "date with embedded CRLF must be rejected");
});

Deno.test("buildVcalendar cannot be made to emit a stray newline (defense in depth)", () => {
  // Even if schema validation were bypassed, compactDate/escape strip control chars.
  const ics = buildVcalendar(
    {
      uid: "e3\r\nX-EVIL:1",
      summary: "ok\r\nX-EVIL:2",
      start: { date: "2026-01-01\r\nX-EVIL:3" } as never,
      end: { date: "2026-01-02" },
    } as never,
    new Date("2026-07-17T00:00:00Z"),
  );
  // No injected property lines: every real line is a known iCal property.
  for (const line of ics.split("\r\n")) {
    if (line === "" || line.startsWith(" ")) continue; // folded continuation
    assert(
      !line.startsWith("X-EVIL"),
      `injected property leaked: ${line}`,
    );
  }
});

// ── octet-aware folding + timezone handling ─────────────────────────────────

Deno.test("foldLine counts UTF-8 octets and never splits a codepoint", () => {
  const folded = foldLine("SUMMARY:" + "😀".repeat(40)); // emoji = 4 octets each
  for (const seg of folded.split("\r\n")) {
    assert(octetLength(seg) <= 75, `segment ${octetLength(seg)} octets > 75`);
  }
  // Round-trips without replacement characters (no split surrogate).
  const rejoined = folded.replace(/\r\n /g, "");
  assert(!rejoined.includes("�"), "a codepoint was split");
  assertEquals(rejoined, "SUMMARY:" + "😀".repeat(40));
});

Deno.test("hasZone distinguishes explicit-offset from floating times", () => {
  assert(hasZone("2026-07-17T09:00:00Z"));
  assert(hasZone("2026-07-17T09:00:00-04:00"));
  assert(!hasZone("2026-07-17T09:00:00"));
});

Deno.test("renderDtLine: floating time uses TZID, offset normalizes to UTC, floating-without-tz throws", () => {
  assertEquals(
    renderDtLine("DTSTART", { dateTime: "2026-07-17T09:00:00", timeZone: "America/New_York" }),
    "DTSTART;TZID=America/New_York:20260717T090000",
  );
  assertEquals(
    renderDtLine("DTEND", { dateTime: "2026-07-17T09:00:00-04:00" }),
    "DTEND:20260717T130000Z",
  );
  assertThrows(() => renderDtLine("DTSTART", { dateTime: "2026-07-17T09:00:00" }));
});

Deno.test("clip strips control chars and caps length", () => {
  assertEquals(clip("a\r\nb\tc"), "a  b c");
  assertEquals(clip("x".repeat(500)).length, 160);
});
