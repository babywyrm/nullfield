# Demo 12 — Response Inspection

Every other gate decides before the call goes upstream. This one decides after:
the tool ran, it returned something it should not have, and nullfield is the
last thing between that and the model's context window.

```bash
demos/12-response-inspection/test.sh
```

Tier 1, no dependencies beyond Docker Compose, gated in CI.

## Opt in per rule, and choose what happens

Inspection is not something the proxy always does. A rule asks for it:

```yaml
- id: report-redact
  action: ALLOW
  toolNames: ["report.fetch"]
  inspection:
    enabled: true
    onFinding: REDACT      # the default when omitted

- id: export-deny
  action: ALLOW
  toolNames: ["export.dump"]
  inspection:
    enabled: true
    onFinding: DENY
```

| `onFinding` | What the caller gets |
|---|---|
| `REDACT` | The response, with each match replaced by `[REDACTED]` |
| `DENY` | Nothing. `-32007`, and the response is discarded |

`REDACT` is surgical — the caller still gets a usable answer minus the part
that should not have been there. `DENY` is the right call when a partial
redaction cannot be trusted: a bulk export that contains one credential
probably contains others in shapes no pattern matches.

The demo's third tool, `debug.echo`, has no `inspection` block and returns the
same content untouched. That control is what makes the rest mean anything.

## What it looks for

Four categories, all pattern-based:

| Category | Catches | Severity |
|---|---|---|
| Credentials | private key headers, `password=`/`api_key:` assignments, `sk-…` keys, bearer tokens, cloud credential assignments | CRITICAL/HIGH |
| PII | US SSNs, email addresses, card-shaped numbers | HIGH/MEDIUM |
| Prompt leaks | system prompt fragments, "never disclose", "respond only with" | HIGH/MEDIUM |
| Internal paths | `/var/run/secrets/kubernetes`, `/etc/shadow`, `*.svc.cluster.local`, `IP:port` | HIGH/MEDIUM |

These are regexes, not a classifier. They catch shapes, so they will miss a
secret that does not look like one and will fire on a support ticket that
quotes an email address. Treat inspection as a backstop for the obvious cases,
not as a guarantee.

## The audit trail is not the leak

A finding is recorded as its category and a count, never the matched text:

```json
{"event_type":"inspection.finding","gate":"inspection",
 "reason":"2 findings: credential: **"}
```

Logging what was caught would defeat the point of catching it.

One caveat the test states out loud: at `NULLFIELD_AUDIT_LOG_LEVEL=FULL` the
*request* arguments are logged, secrets included. In this demo that is visible,
because driving a leak into a response means sending one in as an argument
first. A real leak comes from the upstream and never touches the request — but
it is still a fair warning about running `FULL` against tools whose arguments
carry secrets.

## What is not configurable yet

The categories are all-or-nothing. `spec.rules[].inspection` carries `enabled`
and `onFinding`, and `cmd/nullfield` builds the inspector with
`inspection.DefaultConfig()`, which turns on all four. There is no way to ask
for credential detection and leave email addresses alone.

That matters more than it sounds: the email rule fires on any address, so a
tool that legitimately returns contact details cannot use inspection for
credentials without redacting those too. The test greps for `DefaultConfig()`
and fails if it disappears, so this page gets updated when the gap closes.

## What the test asserts

```
sensitive content is caught on the way back:
  ok:  a credential in the response is redacted
  ok:  the rest of the response survives
  ok:  a different category, PII, is caught by the same rule
  ok:  and so is an internal path

the rule decides what happens next:
  ok:  onFinding: DENY blocks the whole response with -32007
  ok:  and the caller gets none of it

inspection is opt-in per rule:
  ok:  a rule with no inspection block passes the same content through

findings are on the record:
  ok:  the audit trail records the inspection gate
  ok:  and names the category that matched
  ok:  without copying the secret into the finding
  note: at AUDIT_LOG_LEVEL=FULL the request arguments are logged too, secrets included

what is not configurable yet:
  gap: all four detection categories are always on; a rule cannot select between them
```

Nothing here is a real secret. The echo server reflects its arguments, so
sending `password:hunter2xyz123` is enough to get one back in a response
without a purpose-built upstream.

## Related

- Demo 08 also rewrites responses, but from a SCOPE rule's explicit
  `redactResponse` patterns rather than from content detection. SCOPE is for
  fields you know about; inspection is for content you did not expect.
- Demo 01 covers the gates that run before the call goes out.
