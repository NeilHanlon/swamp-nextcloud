import { assert, assertEquals, assertThrows } from "jsr:@std/assert@1";
import {
  addressbookQueryBody,
  addressbookUrl,
  basicAuth,
  buildVcalendar,
  buildVcard,
  calendarQueryBody,
  calendarUrl,
  clip,
  compactDate,
  ContactInputSchema,
  CONTACTS_PROVENANCE_VALUE,
  davBase,
  decodeXmlEntities,
  DeleteContactsArgsSchema,
  DeleteEventsArgsSchema,
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
  icalProp,
  icsHasProvenance,
  mkAddressbookBody,
  mkcalendarBody,
  ocsBase,
  octetLength,
  parseAddressbookReport,
  parseAddressbooks,
  parseCalendarReport,
  parseCalendars,
  parseVcardMinimal,
  PROVENANCE_PROP,
  renderDtLine,
  safePath,
  sanitizeUidForPath,
  toCompactUtc,
  unescapeText,
  utcStamp,
  validateContactUid,
  vcardProp,
  vcardPropAll,
  vcfHasProvenance,
  wallClockInZone,
  xmlEscape,
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

// ── AR-6: recurring events keep their zone (DST-correct expansion) ───────────

Deno.test("wallClockInZone maps any offset to the zone's civil time", () => {
  // 09:00 in a -05:00 offset IS 09:00 wall-clock in New York (winter).
  assertEquals(
    wallClockInZone("2026-01-15T09:00:00-05:00", "America/New_York"),
    "20260115T090000",
  );
  // Same instant expressed as UTC converts to the same NY wall time.
  assertEquals(
    wallClockInZone("2026-01-15T14:00:00Z", "America/New_York"),
    "20260115T090000",
  );
  // A floating (offset-less) input is already local.
  assertEquals(
    wallClockInZone("2026-01-15T09:00:00", "America/New_York"),
    "20260115T090000",
  );
});

Deno.test("renderDtLine preferLocal emits TZID wall-clock for recurring events", () => {
  assertEquals(
    renderDtLine(
      "DTSTART",
      { dateTime: "2026-01-15T09:00:00-05:00", timeZone: "America/New_York" },
      { preferLocal: true },
    ),
    "DTSTART;TZID=America/New_York:20260115T090000",
  );
  // Without preferLocal the zoned time still folds to UTC (single-event path).
  assertEquals(
    renderDtLine(
      "DTSTART",
      { dateTime: "2026-01-15T09:00:00-05:00", timeZone: "America/New_York" },
    ),
    "DTSTART:20260115T140000Z",
  );
  // preferLocal but no timeZone → falls back to UTC folding, never throws.
  assertEquals(
    renderDtLine(
      "DTEND",
      { dateTime: "2026-01-15T09:30:00-05:00" },
      { preferLocal: true },
    ),
    "DTEND:20260115T143000Z",
  );
});

Deno.test("buildVcalendar: recurring timed event carries TZID, not a UTC instant (AR-6)", () => {
  const ics = buildVcalendar(
    {
      uid: "weekly@google.com",
      summary: "Weekly sync",
      start: { dateTime: "2026-01-15T09:00:00-05:00", timeZone: "America/New_York" },
      end: { dateTime: "2026-01-15T09:30:00-05:00", timeZone: "America/New_York" },
      recurrence: ["RRULE:FREQ=WEEKLY;BYDAY=TH"],
    },
    new Date("2026-01-01T00:00:00Z"),
  );
  assert(ics.includes("DTSTART;TZID=America/New_York:20260115T090000\r\n"));
  assert(ics.includes("DTEND;TZID=America/New_York:20260115T093000\r\n"));
  assert(!ics.includes("DTSTART:20260115T140000Z"), "must not fold to UTC");
});

Deno.test("buildVcalendar: single timed event still folds to UTC", () => {
  const ics = buildVcalendar(
    {
      uid: "one@google.com",
      start: { dateTime: "2026-01-15T09:00:00-05:00", timeZone: "America/New_York" },
      end: { dateTime: "2026-01-15T09:30:00-05:00", timeZone: "America/New_York" },
    },
    new Date("2026-01-01T00:00:00Z"),
  );
  assert(ics.includes("DTSTART:20260115T140000Z\r\n"));
});

// ── provenance stamp (X-SWAMP-SYNC) ─────────────────────────────────────────

Deno.test("buildVcalendar stamps every VEVENT with X-SWAMP-SYNC provenance", () => {
  const ics = buildVcalendar({
    uid: "p1",
    start: { date: "2026-12-25" },
    end: { date: "2026-12-26" },
  }, new Date("2026-07-17T00:00:00Z"));
  assert(ics.includes("X-SWAMP-SYNC:gcal-nc-sync\r\n"));
  assert(icsHasProvenance(ics), "icsHasProvenance detects the stamp");
});

Deno.test("icsHasProvenance is false for a foreign (unstamped) event", () => {
  const foreign =
    "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:foreign\r\nDTSTART:20260101T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
  assert(!icsHasProvenance(foreign));
});

// ── iCal property reading / unescaping ──────────────────────────────────────

Deno.test("icalProp reads values, tolerating params and folding", () => {
  const ics =
    "BEGIN:VEVENT\r\nUID:abc@goo\r\n gle.com\r\nDTSTART;TZID=America/New_York:20260115T090000\r\nEND:VEVENT";
  assertEquals(icalProp(ics, "UID"), "abc@google.com"); // unfolded
  assertEquals(icalProp(ics, "DTSTART"), "20260115T090000"); // param stripped
  assertEquals(icalProp(ics, "SUMMARY"), null);
});

Deno.test("unescapeText reverses RFC5545 TEXT escaping", () => {
  assertEquals(unescapeText("a\\; b\\, c\\\\d\\ne"), "a; b, c\\d\ne");
});

Deno.test("decodeXmlEntities decodes the DAV entity set", () => {
  assertEquals(decodeXmlEntities("a&amp;b&lt;c&gt;d"), "a&b<c>d");
});

// ── calendar-query REPORT parsing ───────────────────────────────────────────

const REPORT_FIXTURE = `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response>
    <d:href>/remote.php/dav/calendars/neil/gcal-sync/stamped.ics</d:href>
    <d:propstat><d:prop>
      <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:stamped@google.com
DTSTART:20260115T090000Z
X-SWAMP-SYNC:gcal-nc-sync
END:VEVENT
END:VCALENDAR</cal:calendar-data>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/calendars/neil/gcal-sync/foreign.ics</d:href>
    <d:propstat><d:prop>
      <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:foreign@example.com
DTSTART:20260116T100000Z
END:VEVENT
END:VCALENDAR</cal:calendar-data>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/calendars/neil/gcal-sync/weekly.ics</d:href>
    <d:propstat><d:prop>
      <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:weekly@google.com
DTSTART;TZID=America/New_York:20260107T100000
RRULE:FREQ=WEEKLY;BYDAY=TU
X-SWAMP-SYNC:gcal-nc-sync
END:VEVENT
END:VCALENDAR</cal:calendar-data>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
</d:multistatus>`;

Deno.test("parseCalendarReport extracts uid/dtstart/provenance/isRecurring, no PII", () => {
  const rows = parseCalendarReport(REPORT_FIXTURE);
  assertEquals(rows.length, 3);
  const stamped = rows.find((r) => r.uid === "stamped@google.com")!;
  assertEquals(stamped.dtstart, "20260115T090000Z");
  assertEquals(stamped.hasProvenance, true);
  assertEquals(stamped.isRecurring, false);
  const foreign = rows.find((r) => r.uid === "foreign@example.com")!;
  assertEquals(foreign.hasProvenance, false);
  assertEquals(foreign.isRecurring, false);
  // A recurring master is flagged so window reconciliation never deletes it (ADV-2).
  const weekly = rows.find((r) => r.uid === "weekly@google.com")!;
  assertEquals(weekly.hasProvenance, true);
  assertEquals(weekly.isRecurring, true);
});

// ── request-body builders ───────────────────────────────────────────────────

Deno.test("calendarQueryBody embeds a sanitized time-range and requests marker + RRULE", () => {
  const body = calendarQueryBody("20260101T000000Z", "20260201T000000Z");
  assert(body.includes(`start="20260101T000000Z"`));
  assert(body.includes(`end="20260201T000000Z"`));
  assert(body.includes(`<c:prop name="${PROVENANCE_PROP}"/>`));
  // RRULE is requested so the read side can flag recurring masters (ADV-2).
  assert(body.includes(`<c:prop name="RRULE"/>`));
  // No SUMMARY/DESCRIPTION requested → server returns no PII.
  assert(!body.includes("SUMMARY"));
});

Deno.test("DeleteEventsArgsSchema defaults maxDeletes to a conservative cap", () => {
  const parsed = DeleteEventsArgsSchema.parse({ calendar: "gcal-sync" });
  assertEquals(parsed.maxDeletes, 50);
  assertEquals(parsed.requireProvenance, true);
  assertEquals(parsed.dryRun, false);
  // 0 disables the cap; explicit overrides pass through.
  assertEquals(
    DeleteEventsArgsSchema.parse({ calendar: "c", maxDeletes: 0 }).maxDeletes,
    0,
  );
});

Deno.test("toCompactUtc normalizes an RFC3339 bound and rejects garbage", () => {
  assertEquals(toCompactUtc("2026-01-01T00:00:00Z"), "20260101T000000Z");
  assertEquals(toCompactUtc("2026-01-01T00:00:00-05:00"), "20260101T050000Z");
  assertThrows(() => toCompactUtc("not-a-date"));
});

Deno.test("mkcalendarBody escapes displayname and includes color when given", () => {
  const body = mkcalendarBody("A & B <x>", "#0082c9");
  assert(body.includes("<d:displayname>A &amp; B &lt;x&gt;</d:displayname>"));
  assert(body.includes("<ic:calendar-color>#0082c9</ic:calendar-color>"));
  assert(!mkcalendarBody("plain").includes("calendar-color"));
});

Deno.test("xmlEscape escapes the XML metacharacters", () => {
  assertEquals(xmlEscape(`a&b<c>d"e`), "a&amp;b&lt;c&gt;d&quot;e");
});

// ── CardDAV: URL construction + UID validation ──────────────────────────────

Deno.test("addressbookUrl encodes user + addressbook and trims slashes", () => {
  assertEquals(
    addressbookUrl("https://cloud.example.com", "alice", "/gcontacts-sync/"),
    "https://cloud.example.com/remote.php/dav/addressbooks/users/alice/gcontacts-sync/",
  );
});

Deno.test("validateContactUid accepts safe UIDs and rejects path traversal", () => {
  validateContactUid("abc123");
  validateContactUid("a-b.c_d");
  assertThrows(() => validateContactUid("../admin"));
  assertThrows(() => validateContactUid("a?query"));
  assertThrows(() => validateContactUid("a b"));
  assertThrows(() => validateContactUid(""));
  assertThrows(() => validateContactUid("a".repeat(201)));
});

Deno.test("sanitizeUidForPath replaces unsafe chars and caps length", () => {
  assertEquals(sanitizeUidForPath("a/b\\c"), "a_b_c");
  assertEquals(sanitizeUidForPath("x".repeat(300)).length, 96);
});

// ── CardDAV: VCard 4.0 serializer ──────────────────────────────────────────

Deno.test("buildVcard emits a well-formed VCard 4.0 with all fields", () => {
  const vcf = buildVcard({
    uid: "contact-1",
    fn: "Doe, John",
    n: { family: "Doe", given: "John", additional: "Q", prefix: "Mr", suffix: "Jr" },
    email: [{ value: "john@example.com", type: "WORK" }],
    tel: [{ value: "+1-555-0100", type: "CELL" }],
    adr: [{ street: "123 Main St", locality: "Springfield", region: "IL", code: "62701", country: "US", type: "HOME" }],
    org: "Acme; Corp",
    title: "Engineer, Sr",
    note: "A note",
    bday: "1990-01-15",
    url: "https://example.com",
    categories: ["work", "vip"],
  });
  assert(vcf.startsWith("BEGIN:VCARD\r\n"));
  assert(vcf.trimEnd().endsWith("END:VCARD"));
  assert(vcf.includes("VERSION:4.0\r\n"));
  assert(vcf.includes("UID:contact-1\r\n"));
  assert(vcf.includes("FN:Doe\\, John\r\n"));
  assert(vcf.includes("N:Doe;John;Q;Mr;Jr\r\n"));
  assert(vcf.includes("EMAIL;TYPE=WORK:john@example.com\r\n"));
  assert(vcf.includes("TEL;TYPE=CELL:+1-555-0100\r\n"));
  assert(vcf.includes("ORG:Acme\\; Corp\r\n"));
  assert(vcf.includes("TITLE:Engineer\\, Sr\r\n"));
  assert(vcf.includes("NOTE:A note\r\n"));
  assert(vcf.includes("BDAY:1990-01-15\r\n"));
  assert(vcf.includes("URL:https://example.com\r\n"));
  assert(vcf.includes("CATEGORIES:work,vip\r\n"));
  // Dual provenance (ADV-1)
  assert(vcf.includes("X-SWAMP-SYNC:gcontacts-nc-sync\r\n"));
  assert(vcf.includes("NOTE:Swamp-managed contact (gcontacts-nc-sync)\r\n"));
});

Deno.test("buildVcard rejects a UID with path traversal (SEC-2)", () => {
  assertThrows(() =>
    buildVcard({ uid: "../admin", fn: "Evil" })
  );
});

Deno.test("buildVcard rejects a UID with spaces or query chars", () => {
  assertThrows(() =>
    buildVcard({ uid: "a b", fn: "Spacy" })
  );
  assertThrows(() =>
    buildVcard({ uid: "a?query", fn: "Q" })
  );
});

Deno.test("buildVcard escapes raw CRLF and bare LF in text fields (SEC-1)", () => {
  const vcf = buildVcard({
    uid: "c1",
    fn: "line1\r\nline2\nline3",
  });
  assert(!vcf.includes("FN:line1\r\nline2"));
  assert(vcf.includes("FN:line1\\nline2\\nline3\r\n"));
});

Deno.test("buildVcard escapes trailing backslash", () => {
  const vcf = buildVcard({ uid: "c1", fn: "ends\\" });
  assert(vcf.includes("FN:ends\\\\\r\n"));
});

Deno.test("buildVcard embeds BEGIN:VCARD in FN without injecting a new component", () => {
  const vcf = buildVcard({
    uid: "c1",
    fn: "BEGIN:VCARD\r\nFN:injected",
  });
  // The injected text is escaped, so it can't start a real VCARD component.
  const vcardLines = vcf.split("\r\n");
  const beginCount = vcardLines.filter((l) => l === "BEGIN:VCARD").length;
  assertEquals(beginCount, 1, "only one BEGIN:VCARD allowed");
});

Deno.test("buildVcard rejects NUL in UID (SEC-1 defense in depth)", () => {
  assertThrows(() =>
    buildVcard({ uid: "a\0b", fn: "Nul" })
  );
});

// ── CardDAV: VCard parser ──────────────────────────────────────────────────

Deno.test("vcardProp reads values, tolerating params and folding", () => {
  const vcf = "BEGIN:VCARD\r\nUID:abc@contacts\r\n .gmail.com\r\nFN:John Doe\r\nTEL;TYPE=WORK:555\r\nEND:VCARD";
  assertEquals(vcardProp(vcf, "UID"), "abc@contacts.gmail.com");
  assertEquals(vcardProp(vcf, "FN"), "John Doe");
  assertEquals(vcardProp(vcf, "TEL"), "555");
  assertEquals(vcardProp(vcf, "EMAIL"), null);
});

Deno.test("vcardPropAll returns multiple NOTE values", () => {
  const vcf = "BEGIN:VCARD\r\nNOTE:first\r\nNOTE:second\r\nEND:VCARD";
  assertEquals(vcardPropAll(vcf, "NOTE"), ["first", "second"]);
});

Deno.test("vcfHasProvenance checks exact value, not just presence (ADV-3)", () => {
  const stamped = "BEGIN:VCARD\r\nUID:x\r\nX-SWAMP-SYNC:gcontacts-nc-sync\r\nEND:VCARD";
  const empty = "BEGIN:VCARD\r\nUID:x\r\nX-SWAMP-SYNC:\r\nEND:VCARD";
  const wrong = "BEGIN:VCARD\r\nUID:x\r\nX-SWAMP-SYNC:gcal-nc-sync\r\nEND:VCARD";
  const absent = "BEGIN:VCARD\r\nUID:x\r\nEND:VCARD";
  assertEquals(vcfHasProvenance(stamped), true);
  assertEquals(vcfHasProvenance(empty), false, "empty value must not count");
  assertEquals(vcfHasProvenance(wrong), false, "wrong value must not count");
  assertEquals(vcfHasProvenance(absent), false);
});

Deno.test("vcfHasProvenance falls back to NOTE sentinel (ADV-1)", () => {
  const noteOnly = "BEGIN:VCARD\r\nUID:x\r\nNOTE:Swamp-managed contact (gcontacts-nc-sync)\r\nEND:VCARD";
  assertEquals(vcfHasProvenance(noteOnly), true);
});

Deno.test("parseVcardMinimal extracts uid/fn/provenance and no PII", () => {
  const vcf = "BEGIN:VCARD\r\nUID:c1\r\nFN:John Doe\r\nEMAIL:john@example.com\r\nX-SWAMP-SYNC:gcontacts-nc-sync\r\nEND:VCARD";
  const ref = parseVcardMinimal(vcf);
  assertEquals(ref, { uid: "c1", fn: "John Doe", hasProvenance: true });
  // EMAIL is not in the output — PII minimal.
  const serialized = JSON.stringify(ref);
  assert(!serialized.includes("john@example.com"));
});

Deno.test("VCard round-trip: serialize + parse preserves uid/fn/provenance", () => {
  const input = {
    uid: "round-trip-1",
    fn: "Doe; Jr",
    org: "Acme, Inc",
    categories: ["a", "b"],
  };
  const vcf = buildVcard(input);
  const parsed = parseVcardMinimal(vcf);
  assertEquals(parsed?.uid, input.uid);
  assertEquals(parsed?.fn, input.fn);
  assertEquals(parsed?.hasProvenance, true);
});

// ── CardDAV: PROPFIND + REPORT parsers ──────────────────────────────────────

const ADDRESSBOOK_PROPFIND_FIXTURE = `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response>
    <d:href>/remote.php/dav/addressbooks/alice/</d:href>
    <d:propstat><d:prop>
      <d:displayname>alice</d:displayname>
      <d:resourcetype><d:collection/></d:resourcetype>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/addressbooks/alice/gcontacts-sync/</d:href>
    <d:propstat><d:prop>
      <d:displayname>Google Contacts Sync</d:displayname>
      <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/addressbooks/alice/friends/</d:href>
    <d:propstat><d:prop>
      <d:displayname>Friends</d:displayname>
      <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
</d:multistatus>`;

Deno.test("parseAddressbooks keeps addressbooks, drops bare principal collection", () => {
  const abs = parseAddressbooks(ADDRESSBOOK_PROPFIND_FIXTURE);
  assertEquals(abs.length, 2);
  assertEquals(abs[0].displayName, "Google Contacts Sync");
  assertEquals(abs[0].url, "/remote.php/dav/addressbooks/alice/gcontacts-sync/");
  assertEquals(abs[1].displayName, "Friends");
});

const ADDRESSBOOK_REPORT_FIXTURE = `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response>
    <d:href>/remote.php/dav/addressbooks/neil/gcontacts-sync/stamped.vcf</d:href>
    <d:propstat><d:prop>
      <card:address-data>BEGIN:VCARD
VERSION:4.0
UID:stamped-uid
FN:Stamp Ed
X-SWAMP-SYNC:gcontacts-nc-sync
END:VCARD</card:address-data>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/addressbooks/neil/gcontacts-sync/foreign.vcf</d:href>
    <d:propstat><d:prop>
      <card:address-data>BEGIN:VCARD
VERSION:4.0
UID:foreign-uid
FN:Foreign Person
END:VCARD</card:address-data>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/addressbooks/neil/gcontacts-sync/empty-prov.vcf</d:href>
    <d:propstat><d:prop>
      <card:address-data>BEGIN:VCARD
VERSION:4.0
UID:empty-prov
FN:Empty Prov
X-SWAMP-SYNC:
END:VCARD</card:address-data>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/addressbooks/neil/gcontacts-sync/wrong-prov.vcf</d:href>
    <d:propstat><d:prop>
      <card:address-data>BEGIN:VCARD
VERSION:4.0
UID:wrong-prov
FN:Wrong Prov
X-SWAMP-SYNC:gcal-nc-sync
END:VCARD</card:address-data>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
</d:multistatus>`;

Deno.test("parseAddressbookReport extracts uid/fn/provenance with all four provenance cases (ADV-3)", () => {
  const rows = parseAddressbookReport(ADDRESSBOOK_REPORT_FIXTURE);
  assertEquals(rows.length, 4);
  const stamped = rows.find((r) => r.uid === "stamped-uid")!;
  assertEquals(stamped.fn, "Stamp Ed");
  assertEquals(stamped.hasProvenance, true);
  const foreign = rows.find((r) => r.uid === "foreign-uid")!;
  assertEquals(foreign.hasProvenance, false, "no marker → false");
  const empty = rows.find((r) => r.uid === "empty-prov")!;
  assertEquals(empty.hasProvenance, false, "empty value → false (ADV-3)");
  const wrong = rows.find((r) => r.uid === "wrong-prov")!;
  assertEquals(wrong.hasProvenance, false, "wrong value → false (ADV-3)");
});

Deno.test("parseAddressbookReport NEVER leaks PII fields", () => {
  // Add a VCard with an EMAIL — it must not appear in the parsed output.
  const fixture = `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response>
    <d:href>/x.vcf</d:href>
    <d:propstat><d:prop>
      <card:address-data>BEGIN:VCARD
UID:pii-test
FN:Secret
EMAIL:secret@example.com
TEL:555-1234
END:VCARD</card:address-data>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>`;
  const rows = parseAddressbookReport(fixture);
  const serialized = JSON.stringify(rows);
  assert(!serialized.includes("secret@example.com"));
  assert(!serialized.includes("555-1234"));
});

// ── CardDAV: schema validation + defaults ──────────────────────────────────

Deno.test("ContactInputSchema rejects NUL, path traversal, and oversized UIDs", () => {
  assert(!ContactInputSchema.safeParse({ uid: "a\0b", fn: "x" }).success);
  assert(!ContactInputSchema.safeParse({ uid: "../admin", fn: "x" }).success);
  assert(!ContactInputSchema.safeParse({ uid: "a?b", fn: "x" }).success);
  assert(!ContactInputSchema.safeParse({ uid: "a b", fn: "x" }).success);
  assert(!ContactInputSchema.safeParse({ uid: "a".repeat(201), fn: "x" }).success);
  assert(ContactInputSchema.safeParse({ uid: "valid-uid.1", fn: "ok" }).success);
});

Deno.test("DeleteContactsArgsSchema defaults mirror DeleteEventsArgsSchema", () => {
  const parsed = DeleteContactsArgsSchema.parse({ addressbook: "gcontacts-sync" });
  assertEquals(parsed.maxDeletes, 50);
  assertEquals(parsed.requireProvenance, true);
  assertEquals(parsed.dryRun, false);
});

Deno.test("CONTACTS_PROVENANCE_VALUE is the expected constant (ADV-5)", () => {
  assertEquals(CONTACTS_PROVENANCE_VALUE, "gcontacts-nc-sync");
});

Deno.test("mkAddressbookBody escapes displayname and declares addressbook resourcetype", () => {
  const body = mkAddressbookBody("A & B <x>");
  assert(body.includes("<d:displayname>A &amp; B &lt;x&gt;</d:displayname>"));
  assert(body.includes("<card:addressbook/>"));
});

Deno.test("addressbookQueryBody requests only UID/FN/provenance/NOTE (no PII)", () => {
  const body = addressbookQueryBody();
  assert(body.includes(`<card:prop name="UID"/>`));
  assert(body.includes(`<card:prop name="FN"/>`));
  assert(body.includes(`<card:prop name="${PROVENANCE_PROP}"/>`));
  assert(body.includes(`<card:prop name="NOTE"/>`));
  assert(!body.includes("EMAIL"));
  assert(!body.includes("TEL"));
  assert(!body.includes("ADR"));
});
