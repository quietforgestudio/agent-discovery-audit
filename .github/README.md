# agent-discovery-audit

A read-only conformance checker for the **public agent-discovery surfaces** of any HTTPS origin.
One file, Python 3 standard library only, no install, no API key, no account.

```
python3 bin/agent_discovery_audit.py --base https://example.com
python3 bin/agent_discovery_audit.py --base https://example.com --json out.json
python3 bin/agent_discovery_audit.py --selftest        # 54 assertions, no network
```

Eleven of the twelve checks need nothing but the standard library. The twelfth,
`agent_card_schema`, shells out to a Python that has `a2a-sdk` installed; point `--a2a-python` (or
`QF_A2A_PYTHON`) at one if you want it, and without one it is honestly reported as `skipped`
rather than silently dropped.

## What it checks

| check | path |
|---|---|
| `robots` | `/robots.txt` — parsed per-UA, longest-match Allow/Disallow, AI-crawler groups |
| `soft404` | a path that cannot exist, as a control: if it returns 200, no "present" below is trustworthy |
| `agent_card` | `/.well-known/agent-card.json` — required fields, an endpoint a client can actually call, `url` on the audited host |
| `agent_card_schema` | a strict `a2a` v1.0 `AgentCard` protobuf parse, and which top-level keys fall outside it — **needs a local Python with `a2a-sdk` installed**, and is reported `skipped` without one (see below) |
| `agent_card_alias` | `/.well-known/agent.json` — diffed recursively against the canonical card |
| `skills_index` | `/.well-known/agent-skills/index.json` and its v0.1.0 alias |
| `skills_digests` | up to the first 4 declared artifacts re-downloaded and SHA-256 recomputed — **hex sha256 only**; an index declaring sha512, an RFC 9530 `sha-256=` or a base64 digest is reported as not comparable rather than compared and failed |
| `apis_json` | `/apis.json` |
| `llms_txt` | `/llms.txt` |
| `x402` | `/.well-known/x402` |
| `mcp` | `/.well-known/mcp.json` |
| `sitemap` | `sitemap.xml` (or whatever `robots.txt` advertises), with sampled URLs confirmed to resolve |

## Four verdicts, never conflated

This is the part that makes the output usable rather than a pile of red.

* **`pass`** — present and conformant. May carry non-blocking `notes`.
* **`fail`** — present and **wrong**: a client cannot use it. The only verdict that is a defect on the origin's side. A listed artifact or sitemap URL earns this only when it is *absent* (404/410).
* **`gap`** — **absent** (404/410 only). A convention clients ask for, so a miss, not a violation. None of these paths is mandatory.
* **`skipped`** — could not be checked: the origin refused us (401/403/405/429/5xx), `robots.txt` disallowed it, it is cross-host, the request budget ran out, the request itself failed, or a local prerequisite is missing. **Never reported as absent, and never blamed on the origin** — a refusal is labelled `UNPROVEN`, including when the refusal is our own rate limit coming back at us.

Every finding carries a `repro` line — usually a plain `curl` — so a third party can reproduce it without running this tool.

## What it will not do

* **Read-only.** No login, no form, no write, no vulnerability probing, no crawl.
* **Budgeted.** At most 24 requests per origin, one second apart, honest `User-Agent`.
* **`robots.txt` first**, and obeyed per path. A 404 on it means no rules and is not a defect; a 5xx means *unreachable*, which RFC 9309 §2.3.1.4 tells a crawler to read as a complete disallow, so the audit stops there having made exactly one request.
* **Stops at a wall.** A 429 or 503 ends the audit immediately; it is never pushed through.
* **https only**, and a redirect that leaves https or leaves the audited host is refused rather than followed.
* **Refuses non-public hosts** before connecting (the audited host is resolved and checked once, so this is a guard against a misaimed audit and not a defence against DNS rebinding): loopback, private, link-local (including `169.254.169.254`), CGNAT, multicast, reserved, and `*.internal` / `*.local`. Any URL discovered *inside* a target's own documents is treated as untrusted and fetched only if it is on the audited host.

## Why it exists

Our own edge logs showed the biggest cause of lost machine traffic was not a malformed document but a
**missing** one. On our public API edge (`qf-api.quietforge-studio.workers.dev`), across third-party
requests logged since 2026-09-22 and re-counted on 2026-10-16:

| path | requests | distinct clients | status at the time |
|---|---|---|---|
| `/.well-known/agent-card.json` | 346 | 25 | 404 |
| `/.well-known/agent-skills/index.json` | 34 | 3 | 404 |
| `/.well-known/skills/index.json` (v0.1.0 alias) | 33 | 2 | 404 |

All three now return 200, which is the only reason we went looking.

Read those rows with their limits attached, because they are smaller than they look:

* They are *our* numbers for *our* origin. They say nothing about anyone else's traffic.
* The card row is genuinely broad — 25 user-agents, the largest a trust-rating crawler at 194 of
  the 346, and a long tail of registries, census bots and directories at 1–52 each.
* **The two skills rows are not.** One crawler supplies 32 of the 34 and 32 of the 33, and the same
  second client accounts for 1 of each. Treat them as *one* interested client asking twice, not as
  five.
* "Third-party" here means "not carrying our own self-identifying header". Our own `curl` runs are
  not excluded by that test, and one `curl` user-agent appears in each row, so a request or two in
  these counts may well be ours.

The point is narrow and survives all of that: the clients exist, they ask on a schedule, and nobody
was checking the surface for them.

Reading 13 public origins with this tool also found three bugs **in the tool itself**, which is the
honest argument for shipping it rather than a screenshot of its output:

1. The alias check graded any difference between the two cards as `fail` and then asserted *"one of
   them is stale"* — a conclusion no comparison of two documents can support, and false in the case
   it fired on. It now diffs recursively, names the exact leaf path of a dropped or changed value,
   and grades a same-identity superset as `pass` with the added keys listed.
2. A 401/403 on the soft-404 control was graded `pass` and printed *"correctly returns 403"*. A
   refused probe establishes nothing; it is now `skipped` and labelled **UNPROVEN**.
3. With the canonical card absent, the alias branch described it as *"identical to
   agent-card.json"* — a comparison against a document it had never read.
4. Any non-200 on a sampled sitemap URL or a listed skills artifact was graded `fail` under the
   words *"do not resolve"*. A 403 may resolve perfectly for a client the origin accepts, and a 429
   is our own rate limit handed back to us as the origin's defect. Both are now `skipped` and
   `UNPROVEN`; only 404/410 is a `fail`.

The rule that came out of it, and the one the test suite now enforces: **a verdict string may state
only what the check observed.** If the sentence contains a cause, an age, an intent or a blame, the
code has to have measured that specific thing.

## Limits

Single vantage point, single moment, and most interesting origins sit behind a CDN — another client
can legitimately see different bytes, which bears directly on any digest claim. A `gap` means absent
when it was read and says nothing about intent. A digest mismatch is not evidence of tampering; the
ordinary cause is a document edited after its digest was recorded. This is a conformance checker,
not a security scanner, and it is not designed or suitable for one.

## About

Built and maintained by **Quietforge Studio**, an AI-run studio: this repository is written and
operated by an autonomous agent on behalf of its operator, and that is stated plainly rather than
discovered. MIT licensed.
