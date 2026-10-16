#!/usr/bin/env python3
"""Agent-discovery conformance audit for ANY public HTTPS origin.  (shift 366, 2026-10-16)

WHY THIS EXISTS
  Our own edge census showed the biggest cause of lost machine traffic was not a bad document but a
  MISSING one. On my own public API edge (qf-api.quietforge-studio.workers.dev), over third-party
  requests logged since 2026-09-22: 346 requests from 25 distinct clients to
  /.well-known/agent-card.json while it 404ed there, 34 from 3 clients to
  /.well-known/agent-skills/index.json and 33 from 2 to its v0.1.0 alias /.well-known/skills/index.json
  -- though one crawler accounts for 32 of each of those two, so read them as one interested client
  and not as a crowd. Every agent that publishes a card has the same exposure and nobody checks it
  for them. This is the generalised form of bin/a2a_check.py +
  bin/skills_check.py: same checks, arbitrary origin, structured output, a reproduction command per
  finding.

WHAT IT IS NOT
  Read-only, public pages only. No login, no form, no write, no vulnerability probing, no crawl.
  Hard caps: <= MAX_REQUESTS requests, DELAY s apart, honest User-Agent, robots.txt fetched FIRST and
  obeyed per path (and an unreachable robots.txt stops the audit outright).

NOTE ON THE "shift N" MARKERS BELOW
  This file is written and maintained by an autonomous agent that works in numbered shifts. A
  "shift 365 (critic BLOCKER 1)" comment is a changelog line: it records which review caught the
  defect the code below exists to prevent. Nothing outside this repository is needed to read it.

SAFETY (shift-354 critic, finding M2 — this is a publicly orderable auditor, so base_url and every
URL discovered inside a target's own documents are ATTACKER-CONTROLLED):
  * https only, and a redirect that leaves https or leaves the audited host is refused, not followed.
  * The host must resolve to a PUBLIC IP. Loopback, private, link-local (169.254.169.254),
    carrier-grade NAT, multicast, reserved and *.internal/*.local are refused before any connection.
  * Any URL found inside the target's own documents (skills artifacts, sitemap <loc>) is fetched only
    if it is on the audited host; otherwise the check is `skipped: cross-host`.
  * A 429 or 503 ends the audit immediately (bot wall / rate limit), it is never pushed through.

GRADING -- four verdicts, never conflated. The distinction is the product:
  pass    present and conformant (may carry non-blocking `notes`)
  fail    present and WRONG -- a client cannot use it. The only verdict that blames the target.
  gap     ABSENT (404/410 only). A convention clients ask for, so a miss, not a violation.
  skipped could not be checked: robots.txt disallowed it, the origin refused us (401/403/405/5xx),
          it is cross-host, or a local prerequisite is missing. NEVER reported as absent.

Usage:
  python3 bin/agent_discovery_audit.py --base https://example.com [--json out.json] [--payload]
  python3 bin/agent_discovery_audit.py --selftest
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# A Python that has `a2a-sdk` installed, for the one check that needs a protobuf parse. Shift 365
# (critic MAJOR 4): overridable, because the default path is local to this checkout and a reader who
# cannot set it would otherwise see a permanently `skipped` check with no way to enable it.
VPY = (os.environ.get("QF_A2A_PYTHON")
       or os.path.join(ROOT, "work", "a2a_validate_venv", "bin", "python"))
UA = ("quietforge-discovery-audit/1.0 (+https://quietforge-studio.pages.dev; "
      "read-only conformance audit; one-off, not a crawler)")
MAX_REQUESTS = 24
DELAY = 1.0
TIMEOUT = 20
PAYLOAD_CAP = 8000          # hard cap on a serialized result payload for the delivery surface

AI_CRAWLERS = ("gptbot", "claudebot", "claude-web", "perplexitybot", "google-extended",
               "ccbot", "anthropic-ai", "bytespider", "applebot-extended")

# Paths where we have FIRST-HAND demand evidence from our own edge census, and the count.
# Everything else is labelled "convention only" so no gap carries an unsupported claim (critic M13).
# Shift 365: say WHOSE traffic this is. The figures are from quietforge-studio.pages.dev's own edge
# logs, not from the audited origin, and a reader handed this JSON was reading them as the target's.
# Shift 366: the host named here was WRONG. These rows come from work/x402/inbound.jsonl, which is
# the log of the API worker edge (qf-api.quietforge-studio.workers.dev) -- /v1/pdf/text answers 402
# there and 405 on pages.dev -- not the pages.dev site. And the skills figure summed TWO paths while
# reporting one path's client count. Both corrected against a live re-run of bin/discovery_gaps.py
# on 2026-10-16; the run is saved at work/publish_s366/discovery_gaps_20261016.txt.
MEASURED_DEMAND = {
    "/.well-known/agent-card.json": "346 requests from 25 distinct clients on MY OWN API edge "
                                    "(qf-api.quietforge-studio.workers.dev) while it 404ed there — "
                                    "evidence that clients ask for this path, NOT a measurement of "
                                    "this origin",
    "/.well-known/agent-skills/index.json": "34 requests from 3 distinct clients on MY OWN API edge "
                                            "(qf-api.quietforge-studio.workers.dev) while it 404ed "
                                            "there, plus 33 from 2 clients on the v0.1.0 alias "
                                            "/.well-known/skills/index.json — evidence that clients "
                                            "ask for this path, NOT a measurement of this origin",
}

ABSENT = (404, 410)


class Blocked(Exception):
    """The origin rate-limited us. Stop; never push through a bot wall."""


def host_is_public(host):
    """Resolve and refuse anything that is not a public unicast address."""
    if not host or host.endswith((".internal", ".local", ".localhost")) or host == "localhost":
        return False, "non-public hostname"
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except Exception as e:
        return False, f"dns {type(e).__name__}"
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except Exception:
            return False, "unparseable address"
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback \
                or ip.is_link_local or ip.is_private:
            return False, f"resolves to non-public address {ip}"
    return True, "ok"


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect that leaves https or leaves the audited host."""

    def __init__(self, host):
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        s = urllib.parse.urlsplit(newurl)
        if s.scheme != "https":
            raise urllib.error.URLError(f"refused redirect to non-https {s.scheme}")
        if s.netloc.lower() != self.host:
            raise urllib.error.URLError(f"refused cross-host redirect to {s.netloc}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Fetcher:
    """Budgeted, rate-limited, robots-aware, SSRF-refusing GET."""

    def __init__(self, base):
        s = urllib.parse.urlsplit(base)
        self.scheme = s.scheme
        self.host = s.netloc.lower()
        self.base = f"{s.scheme}://{s.netloc}"
        self.n = 0
        self.last = 0.0
        self.rules = []             # [(ua, "disallow"|"allow", prefix)]
        self.robots_text = ""
        self.robots_status = None
        # Shift 365 (critic MAJOR 5): this used to be a bare `robots_obeyed = True` that was
        # published as if it were a measurement and never written to. Enforcement is STRUCTURAL --
        # get() returns the ROBOTS sentinel without issuing a request -- so what is worth reporting
        # is how many paths that actually refused, which is a real count.
        self.robots_refusals = 0
        self.blocked = False
        self.allow_nonpublic = False   # selftest fixtures only; never set on a real run
        self.opener = urllib.request.build_opener(_SafeRedirect(self.host))

    # -- transport ---------------------------------------------------------
    def _raw(self, url, accept):
        if self.blocked:
            return "BLOCKED", b"", {}, None
        if self.n >= MAX_REQUESTS:
            return "BUDGET", b"", {}, None
        gap = DELAY - (time.time() - self.last)
        if gap > 0:
            time.sleep(gap)
        self.n += 1
        self.last = time.time()
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
        try:
            with self.opener.open(req, timeout=TIMEOUT) as r:
                body = r.read(400_001)
                h = dict(r.headers)
                h["_final_url"] = r.geturl()
                h["_truncated"] = len(body) > 400_000
                return r.status, body[:400_000], h, None
        except urllib.error.HTTPError as e:
            if e.code in (429, 503):
                self.blocked = True
            try:
                body = e.read(20_000)
            except Exception:
                body = b""
            return e.code, body, dict(e.headers or {}), None
        except Exception as e:
            return None, b"", {}, f"{type(e).__name__}: {str(e)[:90]}"

    # -- robots ------------------------------------------------------------
    def load_robots(self):
        ok, why = (True, "ok") if self.allow_nonpublic else host_is_public(self.host)
        if not ok:
            self.robots_status = "REFUSED"
            self.refuse_reason = why
            return
        st, body, h, err = self._raw(self.base + "/robots.txt", "text/plain, */*")
        self.robots_status = st
        self.robots_error = err
        if st != 200 or not body:
            return
        self.robots_text = body.decode("utf-8", "replace")
        agents, pending = [], True       # accumulate consecutive User-agent lines (critic M11)
        for line in self.robots_text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            k, v = (p.strip() for p in line.split(":", 1))
            kl = k.lower()
            if kl == "user-agent":
                if not pending:
                    agents, pending = [], True
                agents.append(v.lower())
            elif kl in ("disallow", "allow"):
                pending = False
                if v:
                    for a in agents or ["*"]:
                        self.rules.append((a, kl, v))

    def _ua_matches(self, ua):
        """`*`, or a token that is a prefix of our product token (robots UA matching is
        case-insensitive and substring-ish; an origin writing `quietforge-discovery-audit/1.0`
        must still match us -- shift 365 critic MINOR 10)."""
        if ua == "*":
            return True
        me = UA.split()[0].lower()                     # quietforge-discovery-audit/1.0
        return ua in me or me.split("/")[0] in ua

    @staticmethod
    def _pattern_re(pref):
        """A robots path pattern -> regex. `*` is any run, a trailing `$` anchors the end.

        Shift 365 (critic BLOCKER 2): matching used to be a bare `path.startswith(pref)`, so every
        wildcard pattern -- `Disallow: /*`, `/*.json$`, `/*?*sort=`, `/mcp/servers/*/admin`, all
        widely used and honoured by major crawlers -- matched NOTHING, and the tool would have
        fetched a path the origin had disallowed while four separate strings claimed otherwise.
        (Checked over the 13-origin census: only one origin used wildcard patterns and none of them
        covered a path this audit requests, so no request in that run was actually non-compliant --
        but the guard was not doing its job.)
        """
        anchored = pref.endswith("$")
        body = pref[:-1] if anchored else pref
        rx = "".join(".*" if ch == "*" else re.escape(ch) for ch in body)
        return re.compile("^" + rx + ("$" if anchored else ""))

    def allowed(self, path):
        """Longest-match Allow/Disallow for * or our own UA token, wildcards honoured."""
        best = None
        for ua, kind, pref in self.rules:
            if not self._ua_matches(ua):
                continue
            if self._pattern_re(pref).match(path):
                if best is None or len(pref) > len(best[1]):
                    best = (kind, pref)
        return best is None or best[0] == "allow"

    def blocks_ai_crawlers(self):
        """UAs given a blanket disallow. `/` and `/*` are the same instruction."""
        return sorted({ua for ua, kind, pref in self.rules
                       if ua in AI_CRAWLERS and kind == "disallow"
                       and pref.rstrip("*") == "/"})

    # -- public API --------------------------------------------------------
    def get(self, url_or_path, accept="application/json, text/plain, */*"):
        """Returns (status, body, headers, err). status may be the sentinel strings
        ROBOTS / CROSSHOST / BUDGET / BLOCKED / REFUSED."""
        if url_or_path.startswith("http"):
            s = urllib.parse.urlsplit(url_or_path)
            if s.scheme != "https":
                return "CROSSHOST", b"", {}, "not https"
            if s.netloc.lower() != self.host:
                return "CROSSHOST", b"", {}, f"host {s.netloc}"
            path, url = s.path or "/", url_or_path
        else:
            path, url = url_or_path, self.base + url_or_path
        if not self.allowed(path):
            self.robots_refusals += 1
            return "ROBOTS", b"", {}, None
        st, body, h, err = self._raw(url, accept)
        if isinstance(st, int) and st == 200 and h.get("_final_url"):
            fs = urllib.parse.urlsplit(h["_final_url"])
            if fs.scheme != "https" or fs.netloc.lower() != self.host:
                return "CROSSHOST", b"", h, f"redirected to {h['_final_url'][:80]}"
        return st, body, h, err


def chk(cid, path, verdict, detail, repro=None, base="", notes=None):
    c = {"id": cid, "path": path, "verdict": verdict, "detail": detail,
         "repro": repro or (f"curl -sS -D- -o/dev/null '{base}{path}'" if path else "")}
    if notes:
        c["notes"] = notes
    return c


def _json(body):
    try:
        return json.loads(body.decode("utf-8", "replace")), None
    except Exception as e:
        return None, str(e)[:140]


def _ct(h):
    return (h.get("Content-Type") or h.get("content-type") or "").lower()


def _unreachable(cid, path, st, err, base):
    """Map every non-200, non-absent outcome to `skipped` with the real reason.
    404/410 is the ONLY thing that means absent (critic M4)."""
    if st == "ROBOTS":
        return chk(cid, path, "skipped", "robots.txt disallows this path", base=base)
    if st == "CROSSHOST":
        return chk(cid, path, "skipped", f"not fetched: off the audited host ({err})", base=base)
    if st == "BUDGET":
        return chk(cid, path, "skipped", "request budget exhausted before this check", base=base)
    if st == "BLOCKED":
        return chk(cid, path, "skipped", "audit stopped: the origin rate-limited us (429/503)",
                   base=base)
    if st is None:
        return chk(cid, path, "skipped", f"request failed ({err})", base=base)
    if st in ABSENT:
        d = MEASURED_DEMAND.get(path)
        return chk(cid, path, "gap",
                   f"HTTP {st}. " + (f"Demand measured: {d}." if d
                                     else "No third-party demand for this path measured on my own "
                                          "edge — convention only."), base=base)
    return chk(cid, path, "skipped",
               f"HTTP {st} — the origin did not serve it to me, so I cannot tell present from "
               f"absent", base=base)


def audit(base, f=None):
    base = base.rstrip("/")
    f = f or Fetcher(base)
    out = []
    f.load_robots()

    if f.robots_status == "REFUSED":
        return _result(base, f, [chk("origin", "", "skipped",
                                     f"refused before any request: {f.refuse_reason}")],
                       unreachable=True)

    # Shift 366 (critic MAJOR 5): a 5xx on /robots.txt is "unreachable" in RFC 9309 s2.3.1.4, and a
    # crawler is told to assume COMPLETE DISALLOW. We used to leave the rule set empty and then
    # issue ~23 more requests, which is the opposite of the README's "robots.txt first, and obeyed".
    if isinstance(f.robots_status, int) and 500 <= f.robots_status <= 599:
        return _result(base, f, [chk("robots", "/robots.txt", "skipped",
                                     f"HTTP {f.robots_status} — RFC 9309 s2.3.1.4 treats an "
                                     f"unreachable robots.txt as a complete disallow, so the audit "
                                     f"stopped here and made no further request", base=base,
                                     repro=f"curl -sSI {base}/robots.txt")],
                       unreachable=True)

    # ---- 1. robots.txt. ABSENT robots.txt is VALID and unrestrictive -- not a gap (critic M13).
    if f.robots_status == 200:
        sm = re.findall(r"(?im)^sitemap:\s*(\S+)", f.robots_text)
        blocked = f.blocks_ai_crawlers()
        det = (f"200, {sum(1 for r in f.rules if r[1] == 'disallow')} Disallow and "
               f"{sum(1 for r in f.rules if r[1] == 'allow')} Allow rule(s); "
               f"{len(sm)} Sitemap line(s)")
        notes = ([f"blocks {len(blocked)} named AI crawler(s) at /: " + ", ".join(blocked)]
                 if blocked else None)
        out.append(chk("robots", "/robots.txt", "pass", det, base=base, notes=notes))
    elif isinstance(f.robots_status, int) and f.robots_status in ABSENT:
        sm = []
        out.append(chk("robots", "/robots.txt", "pass",
                       f"HTTP {f.robots_status} — no robots.txt. That is valid and unrestrictive; "
                       f"the only cost is that no Sitemap location is advertised.", base=base))
    else:
        sm = []
        out.append(_unreachable("robots", "/robots.txt", f.robots_status,
                                getattr(f, "robots_error", None), base))

    # ---- 2. soft-404 control, BEFORE any 200 below is trusted.
    probe = "/.well-known/__qf_audit_probe_7f3a91"
    st, body, h, err = f.get(probe)
    if isinstance(st, int):
        soft404 = (st == 200)
        if soft404:
            out.append(chk("soft404", probe, "fail",
                           "a path that cannot exist returns 200 — this origin cannot tell a machine "
                           "client a miss from a hit, and no 'present' result below is reliable",
                           base=base))
        elif st in ABSENT:
            out.append(chk("soft404", probe, "pass",
                           f"a nonexistent well-known path correctly returns {st}", base=base))
        else:
            # Shift 365: a 401/403/405/5xx on the probe was being graded PASS and printed as
            # "correctly returns 403", which it is not -- the origin refused the probe, so the
            # control was never established. A bot-walled origin scored its only pass this way.
            # Real 404s below are still read as gaps (conservative), but say the control is unproven.
            out.append(chk("soft404", probe, "skipped",
                           f"HTTP {st} — the origin refused the probe, so the soft-404 control is "
                           "UNPROVEN. A 404 below is still read as absent, but a 200 cannot be "
                           "cross-checked against a known-missing path", base=base))
    else:
        soft404 = None
        out.append(_unreachable("soft404", probe, st, err, base))

    if f.blocked:
        return _result(base, f, out, unreachable=True)

    def present(st):
        return st == 200 and not soft404

    # ---- 3. A2A agent card.
    card = None
    P = "/.well-known/agent-card.json"
    st, body, h, err = f.get(P)
    if not isinstance(st, int) or st != 200:
        out.append(_unreachable("agent_card", P, st, err, base))
    elif soft404:
        out.append(chk("agent_card", P, "skipped",
                       "200, but this origin 200s paths that cannot exist, so presence is "
                       "unverifiable here", base=base))
    else:
        card, perr = _json(body)
        if perr:
            out.append(chk("agent_card", P, "fail", f"200 but not parseable JSON: {perr}", base=base))
        else:
            # A defect breaks a client or contradicts the document's own claim. Anything softer is
            # a note. (shift 354: requiring `url` was a false positive on our own v1.0 card.)
            bad, soft = [], []
            if "json" not in _ct(h):
                soft.append(f"Content-Type is {_ct(h) or '<none>'}, not application/json")
            missing = [k for k in ("name", "description", "version", "skills") if k not in card]
            if missing:
                bad.append("missing required field(s): " + ", ".join(missing))
            if not any(k in card for k in ("url", "supportedInterfaces", "additionalInterfaces")):
                bad.append("no endpoint declared: none of url (v0.3), supportedInterfaces or "
                           "additionalInterfaces (v1.0) is present, so a client that reads the card "
                           "still does not know where to call")
            xk = [k for k in card if k.startswith("x-")]
            if xk:
                soft.append(f"non-schema key(s) {xk}: strict parsers reject unknown top-level keys")
            if isinstance(card.get("url"), str) and card["url"]:
                hc = urllib.parse.urlsplit(card["url"]).netloc
                if hc and hc.lower() != f.host:
                    bad.append(f"card.url host {hc} is not the host serving the card ({f.host})")
            if isinstance(card.get("skills"), list) and not card["skills"]:
                bad.append("skills is an empty list — the card advertises no capability")
            if isinstance(card.get("capabilities"), dict) \
                    and card["capabilities"].get("extensions") == []:
                soft.append("capabilities.extensions is present but empty (valid; omitting is tidier)")
            out.append(chk("agent_card", P, "fail" if bad else "pass",
                           "; ".join(bad) if bad else
                           f"200, valid JSON, required fields present, "
                           f"{len(card.get('skills') or [])} skill(s) declared",
                           base=base, notes=soft or None))

        if card is not None and not perr:
            out.append(_schema_check(card, base, P))

    # ---- 4. legacy alias. This path ALSO carries non-A2A payment manifests.
    A = "/.well-known/agent.json"
    st, body, h, err = f.get(A)
    if not isinstance(st, int) or st != 200:
        out.append(_unreachable("agent_card_alias", A, st, err, base))
    elif soft404:
        out.append(chk("agent_card_alias", A, "skipped", "unverifiable under a soft 404", base=base))
    else:
        alias, aerr = _json(body)
        looks_a2a = isinstance(alias, dict) and (
            "skills" in alias or "protocolVersion" in alias
            or ("name" in alias and "capabilities" in alias))
        if aerr:
            out.append(chk("agent_card_alias", A, "fail", f"200 but not parseable JSON: {aerr}",
                           base=base))
        elif not looks_a2a:
            out.append(chk("agent_card_alias", A, "pass",
                           "200, valid JSON, but not an AgentCard shape — a different manifest "
                           "lives at this path, so it is not compared to the card", base=base))
        elif card is not None and alias != card:
            # Shift 365: the old text here asserted "one of them stale", which the data does not
            # support -- on one audited origin both cards carried the SAME name and version and
            # the same 16 skills, and the alias was a strict SUPERSET. Say what differs instead,
            # and grade a pure superset as a pass with a note, not a fail.
            ka, kc = set(alias), set(card)
            added, removed = sorted(ka - kc), sorted(kc - ka)
            # A nested-only addition (one audited origin adds a key under capabilities) is an
            # EXTENSION, not a contradiction, so compare recursively and report the leaf path.
            changed = sorted(p for k in (ka & kc) for p in _value_conflicts(k, alias[k], card[k]))
            same_identity = all(alias.get(k) == card.get(k) for k in ("name", "version"))
            nested_adds = sorted(k for k in (ka & kc) if alias[k] != card[k]
                                 and not _value_conflicts(k, alias[k], card[k]))
            parts = []
            if added:
                parts.append("keys only in the alias: " + ", ".join(added[:12]))
            if removed:
                parts.append("keys only in agent-card.json: " + ", ".join(removed[:12]))
            if nested_adds:
                parts.append("extra nested keys under: " + ", ".join(nested_adds[:12]))
            if changed:
                parts.append("same key, different value: " + ", ".join(changed[:12]))
            detail = "200, AgentCard shape, but NOT byte-identical to agent-card.json — " \
                     + ("; ".join(parts) if parts else "the two documents differ")
            if not removed and not changed and same_identity:
                out.append(chk("agent_card_alias", A, "pass",
                               detail + ". Same name and version, alias is a strict superset, so "
                               "this reads as an extension of the card rather than a second "
                               "divergent copy; a strict a2a client reading the alias still sees "
                               "unknown top-level keys", base=base))
            else:
                out.append(chk("agent_card_alias", A, "fail",
                               detail + ". A client cannot tell which document is current",
                               base=base))
        elif card is None:
            # Shift 365: this branch used to claim the alias was "identical to agent-card.json"
            # when agent-card.json had 404ed, i.e. compared against a document it never read.
            out.append(chk("agent_card_alias", A, "pass",
                           "200, AgentCard shape at the legacy path, and the canonical "
                           "/.well-known/agent-card.json was NOT readable, so the two are not "
                           "compared — a strict a2a client that only asks for the canonical path "
                           "sees nothing", base=base))
        else:
            out.append(chk("agent_card_alias", A, "pass",
                           "legacy alias present and identical to agent-card.json", base=base))

    # ---- 5. agent-skills index (ONE check for the canonical path + its alias) + digest integrity.
    out.extend(_skills(f, base, soft404))

    # ---- 6. other manifests clients ask for.
    for cid, p, want_json in (("apis_json", "/apis.json", True),
                              ("llms_txt", "/llms.txt", False),
                              ("x402", "/.well-known/x402", True),
                              ("mcp", "/.well-known/mcp.json", True)):
        st, body, h, err = f.get(p)
        if not isinstance(st, int) or st != 200:
            out.append(_unreachable(cid, p, st, err, base))
        elif soft404:
            out.append(chk(cid, p, "skipped", "unverifiable under a soft 404", base=base))
        elif want_json:
            d, perr = _json(body)
            out.append(chk(cid, p, "fail" if perr else "pass",
                           f"200 but not parseable JSON: {perr}" if perr
                           else f"200, valid JSON ({len(body)} bytes)", base=base))
        else:
            out.append(chk(cid, p, "pass", f"200, {len(body)} bytes", base=base))

    # ---- 7. sitemap.
    out.extend(_sitemap(f, base, sm, soft404))
    return _result(base, f, out)


def _value_conflicts(path, newv, oldv, _depth=0):
    """Leaf paths where `newv` CONTRADICTS `oldv`, ignoring keys `newv` merely adds.

    Written shift 365. The alias check used to grade any `!=` as drift and then assert that one of
    the two documents was stale -- an inference it had no way to make. One audited origin's alias differs
    from its card only by ADDED keys (10 at the top level, plus capabilities.stateTransitionHistory
    nested one level down), with the same name, version and 16 skills, so "one of them is stale"
    was false. Addition is an extension; a different value for the same leaf is a real conflict.
    """
    if newv == oldv:
        return []
    if isinstance(newv, dict) and isinstance(oldv, dict) and _depth < 6:
        out = []
        for k in oldv:                      # a key the alias DROPS is a conflict
            if k not in newv:
                out.append(f"{path}.{k} (absent in the alias)")
            else:
                out += _value_conflicts(f"{path}.{k}", newv[k], oldv[k], _depth + 1)
        return out
    return [path]


def _schema_check(card, base, P):
    repro = ("python3 -m venv /tmp/v && /tmp/v/bin/pip install a2a-sdk==1.2.2 && curl -sS "
             f"'{base}{P}' | /tmp/v/bin/python -c \"import json,sys;"
             "from google.protobuf import json_format;import a2a.types as t;"
             "json_format.ParseDict(json.load(sys.stdin), t.AgentCard());print('OK')\"")
    if not os.path.exists(VPY):
        return chk("agent_card_schema", P, "skipped",
                   "strict a2a parse skipped: no Python with a2a-sdk available "
                   "(pass --a2a-python or set QF_A2A_PYTHON)", repro=repro)
    code = ("import json,sys\n"
            "from google.protobuf import json_format\n"
            "import a2a.types as t\n"
            "d=json.load(sys.stdin)\n"
            "allowed=set()\n"
            "for fd in t.AgentCard.DESCRIPTOR.fields: allowed.add(fd.json_name); allowed.add(fd.name)\n"
            "extra=[k for k in d if k not in allowed]\n"
            "strict=lenient=None\n"
            "try:\n"
            " json_format.ParseDict(d, t.AgentCard())\n"
            "except Exception as e: strict=str(e).splitlines()[0]\n"
            "try:\n"
            " json_format.ParseDict(d, t.AgentCard(), ignore_unknown_fields=True)\n"
            "except Exception as e: lenient=str(e).splitlines()[0]\n"
            "print(json.dumps({'extra':extra,'strict':strict,'lenient':lenient}))")
    pr = subprocess.run([VPY, "-c", code], input=json.dumps(card), text=True, capture_output=True)
    try:
        v = json.loads((pr.stdout or "").strip().splitlines()[-1])
    except Exception:
        return chk("agent_card_schema", P, "skipped",
                   f"local validator returned no verdict ({(pr.stderr or '').strip()[-120:]})",
                   repro=repro)
    if not v["strict"]:
        return chk("agent_card_schema", P, "pass",
                   "parses strictly against the a2a v1.0 AgentCard protobuf schema "
                   "(a2a-sdk 1.2.2), with no unknown top-level keys", repro=repro)
    if v["lenient"]:
        # Fails even when unknown fields are ignored: a real shape/type violation.
        return chk("agent_card_schema", P, "fail",
                   "the a2a v1.0 AgentCard schema rejects this document even with "
                   f"ignore_unknown_fields=True, so no client using the official SDK's protobuf "
                   f"type can parse it: {v['lenient'][:200]}", repro=repro)
    # Parses once unknown fields are ignored -> an interoperability note, NOT a defect. The A2A
    # spec text we could find states no rule either way, so grading it `fail` would be an
    # invented finding (shift-354 critic, M6/M7).
    extra = v["extra"]
    return chk("agent_card_schema", P, "pass",
               "parses with ignore_unknown_fields=True but NOT with the default strict parse: "
               f"{v['strict'][:120]}"
               + (f"; {len(extra)} top-level key(s) are outside the v1.0 schema: "
                  + ", ".join(extra[:12]) if extra else ""),
               repro=repro,
               notes=["a2a-sdk 1.2.2 exposes AgentCard as a protobuf message, and "
                      "json_format.ParseDict is strict by default — a client that does not pass "
                      "ignore_unknown_fields=True drops the whole card. The schema-safe home for "
                      "ecosystem fields is capabilities.extensions. Reported as a compatibility "
                      "note, not a defect: the spec text states no rule on unknown fields."])


def _skills(f, base, soft404):
    CANON = "/.well-known/agent-skills/index.json"
    ALIAS = "/.well-known/skills/index.json"
    idx, idx_path, last = None, None, None
    for p in (CANON, ALIAS):
        st, body, h, err = f.get(p)
        last = (p, st, err)
        if isinstance(st, int) and st == 200 and not soft404:
            d, perr = _json(body)
            if perr:
                return [chk("skills_index", p, "fail", f"200 but not parseable JSON: {perr}",
                            base=base)]
            idx, idx_path = d, p
            break
    if idx is None:
        p, st, err = last
        c = _unreachable("skills_index", CANON, st, err, base)
        if c["verdict"] == "gap":
            c["detail"] += f" Neither {CANON} nor its v0.1.0 alias {ALIAS} is served."
        return [c]

    out = [chk("skills_index", idx_path, "pass",
               f"200, {len(idx.get('skills') or []) if isinstance(idx, dict) else 0} skill entr(ies)"
               + (" (served at the v0.1.0 alias path)" if idx_path == ALIAS else ""), base=base)]
    all_entries = [s for s in (idx.get("skills") or []) if isinstance(s, dict)] \
        if isinstance(idx, dict) else []
    SAMPLE_CAP = 4
    entries = all_entries[:SAMPLE_CAP]
    bad, ok, nodigest, skipped, nourl, otheralg = [], 0, 0, 0, 0, []
    for s in entries:
        url = s.get("url") or s.get("href") or s.get("path")
        # Shift 365 (critic BLOCKER 1): this used to take whatever followed the last ":" and compare
        # it to a SHA-256 hex with no algorithm or format check, so an index declaring `sha512:…`,
        # `sha-256=…` (RFC 9530) or a base64 digest produced a GUARANTEED mismatch -- published as
        # "declared sha256 <not-a-sha256>… but the served bytes hash to …", i.e. an accusation in the
        # wording of an algorithm the origin never declared. Only sha256 hex is comparable here.
        raw = str(s.get("digest") or s.get("sha256") or s.get("checksum") or "").strip()
        alg, _, val = raw.rpartition(":") if ":" in raw else ("", "", raw)
        val = val.strip().lower()
        alg = alg.strip().lower()
        declared = val if re.fullmatch(r"[0-9a-f]{64}", val) and alg in ("", "sha256", "sha-256") \
            else ""
        if raw and not declared:
            otheralg.append(f"{s.get('id') or url or '?'}: declares "
                            f"{(alg or 'a non-sha256') + ' digest'}, which this audit does not "
                            f"compute, so it is NOT compared")
        if not url:
            nourl += 1
            continue
        full = url if str(url).startswith("http") else base + str(url)
        st2, b2, h2, e2 = f.get(full, "text/markdown, text/plain, */*")
        if not isinstance(st2, int):
            skipped += 1
            continue
        if st2 in ABSENT:
            bad.append(f"{s.get('id') or url}: the index lists it but the artifact is absent "
                       f"(HTTP {st2})")
            continue
        if st2 != 200 or not b2:
            # Shift 366 (critic BLOCKER 1): a 401/403/405/429/5xx on a listed artifact is the origin
            # refusing US. It does not show the listing is wrong, so it is UNPROVEN, not a `fail`.
            otheralg.append(f"{s.get('id') or url}: returned HTTP {st2}"
                            + ("" if b2 else " with an empty body")
                            + ", so its digest could not be checked (UNPROVEN)")
            skipped += 1
            continue
        if not declared:
            nodigest += 1
            continue
        got = hashlib.sha256(b2).hexdigest()
        if got != declared:
            bad.append(f"{s.get('id') or url}: declared sha256 {declared[:12]}… but the served "
                       f"bytes hash to {got[:12]}…")
        else:
            ok += 1
    if all_entries:
        scope = (f"{len(entries)} of {len(all_entries)} index entr(ies) examined"
                 + (f" (cap {SAMPLE_CAP})" if len(all_entries) > SAMPLE_CAP else ""))
        det = (f"{ok} artifact(s) re-downloaded and SHA-256 matched; {scope}"
               + (f"; {nodigest} published no digest to check" if nodigest else "")
               + (f"; {nourl} entr(ies) declare no url" if nourl else "")
               + (f"; {skipped} not fetched (cross-host or budget)" if skipped else ""))
        out.append(chk("skills_digests", idx_path, "fail" if bad else "pass",
                       ("; ".join(bad) + f" [{scope}]") if bad else det,
                       repro="re-GET each skills[].url from the index and compare sha256 of the "
                             "bytes to skills[].digest",
                       notes=otheralg or None))
    return out


def _sitemap(f, base, sm_lines, soft404):
    same_host = [u for u in sm_lines
                 if urllib.parse.urlsplit(u).netloc.lower() in ("", f.host)]
    target = same_host[0] if same_host else base + "/sitemap.xml"
    shown = urllib.parse.urlsplit(target).path or "/sitemap.xml"
    st, body, h, err = f.get(target, "application/xml, text/xml, */*")
    if not isinstance(st, int) or st != 200:
        return [_unreachable("sitemap", shown, st, err, base)]
    if soft404:
        return [chk("sitemap", shown, "skipped", "unverifiable under a soft 404", base=base)]
    ct = _ct(h)
    enc = (h.get("Content-Encoding") or h.get("content-encoding") or "").lower()
    if target.endswith(".gz") or "gzip" in enc or body[:2] == b"\x1f\x8b":
        return [chk("sitemap", shown, "skipped",
                    "200, gzipped sitemap — valid, but this audit does not decompress it",
                    base=base)]
    locs = re.findall(rb"<loc>\s*([^<\s]+)\s*</loc>", body)
    if not locs:
        if "xml" not in ct and b"<urlset" not in body[:400] and b"<sitemapindex" not in body[:400]:
            return [chk("sitemap", shown, "skipped",
                        f"200 but Content-Type is {ct or '<none>'} and the body is not XML — not "
                        f"parsed as a sitemap rather than graded against one", base=base)]
        if h.get("_truncated"):
            return [chk("sitemap", shown, "skipped",
                        "200, XML, but larger than this audit's 400 KB read cap — not parsed",
                        base=base)]
        return [chk("sitemap", shown, "fail",
                    "200 and served as XML but it contains no <loc> entries, so it lists nothing",
                    base=base)]
    n = f"{len(locs)}+" if h.get("_truncated") else str(len(locs))
    # Shift 366 (critic BLOCKER 1): every non-200 used to land in `dead` under the wording
    # "URL(s) the sitemap lists do not resolve", graded `fail`. A 401/403/405/429/5xx is the origin
    # REFUSING US -- the URL may resolve perfectly for a client it accepts -- so that verdict
    # asserted something the check never observed, and on 429 it blamed the origin for our own rate
    # limit. Only ABSENT (404/410) proves the listing is broken. A refusal is now UNPROVEN.
    checked, dead, refused, off, live = 0, [], [], 0, 0
    for u in locs[:3]:
        uu = u.decode("utf-8", "replace")
        st3, _, _, _ = f.get(uu, "text/html, */*")
        if not isinstance(st3, int):
            off += 1
            continue
        checked += 1
        if st3 == 200:
            live += 1
        elif st3 in ABSENT:
            dead.append(f"{uu} -> HTTP {st3}")
        else:
            refused.append(f"{uu} -> HTTP {st3}")
    tail = ((f"; {off} not sampled (cross-host, robots or budget)" if off else "")
            + (f"; {len(refused)} returned a status that neither confirms nor denies the listing "
               f"(UNPROVEN): " + "; ".join(refused) if refused else ""))
    if dead:
        v, det = "fail", ("URL(s) the sitemap lists are absent: " + "; ".join(dead) + tail)
    elif live:
        v, det = "pass", (f"200, {n} URL(s); sampled {checked}, {live} returned 200" + tail)
    elif checked:
        v, det = "skipped", (f"200, {n} URL(s), but every sampled URL was refused, so none was "
                             f"verified (UNPROVEN)" + tail)
    else:
        v, det = "skipped", (f"200, {n} URL(s); none could be sampled" + tail)
    return [chk("sitemap", shown, v, det,
                repro=f"curl -sS '{target}' | grep -o '<loc>[^<]*' | head -3")]


def _result(base, f, checks, unreachable=False):
    summary = {}
    for c in checks:
        summary[c["verdict"]] = summary.get(c["verdict"], 0) + 1
    return {
        "service": "agent-discovery-conformance-audit",
        "version": "1.1.0",
        "base_url": base,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "requests_made": f.n,
        "request_budget": MAX_REQUESTS,
        "robots_txt_status": f.robots_status,
        "robots_txt_enforcement": {
            "mode": "structural — a disallowed path is refused before any request is issued",
            "paths_refused_by_robots": f.robots_refusals},
        "rate_limited_by_origin": f.blocked,
        "origin_unreachable": bool(unreachable),
        # Shift 365 (critic BLOCKER 1): this mapped `verdict == "fail"` to a bool, so a SKIPPED
        # soft404 -- the origin refused the probe -- came out False and was published as "pass",
        # in the JSON and in to_payload's method string of a PAID deliverable. Read the verdict.
        "soft_404_control": {"fail": "fail", "pass": "pass", "skipped": "unproven"}.get(
            next((c["verdict"] for c in checks if c["id"] == "soft404"), None), "unknown"),
        "grading": {"pass": "present and conformant",
                    "fail": "present and wrong — a client cannot use it",
                    "gap": "absent (404/410 only) — a convention clients ask for, not a violation",
                    "skipped": "could not be checked (robots, origin refusal, cross-host, budget)"},
        "scope_not_covered": ["authentication", "any write or form submission",
                              "vulnerability probing", "load or rate-limit testing",
                              "page content quality", "anything behind a login"],
        "checks": checks,
        "summary": summary,
    }


# ---------------------------------------------------------------- deliverable payload
def to_payload(r, cap=PAYLOAD_CAP):
    """The exact shape a paid delivery promises, hard-bounded to `cap` serialized chars."""
    sev = {"fail": 0, "gap": 1}
    find = sorted([c for c in r["checks"] if c["verdict"] in sev],
                  key=lambda c: (sev[c["verdict"]], c["id"]))
    def row(c):
        return {"id": c["id"][:32], "path": c["path"][:140], "verdict": c["verdict"][:8],
                "detail": c["detail"][:400], "repro": c["repro"][:200]}
    p = {
        "base_url": r["base_url"][:300],
        "checked_at": r["checked_at"][:40],
        "method": (f"{r['requests_made']} of {r['request_budget']} allowed requests, >=1 s apart, "
                   f"single User-Agent; robots.txt HTTP {r['robots_txt_status']} and obeyed per "
                   f"path; read-only, public paths only; "
                   f"soft-404 control: {r['soft_404_control']}"
                   + ("; ORIGIN RATE-LIMITED US, audit stopped early"
                      if r["rate_limited_by_origin"] else ""))[:500],
        "soft_404_control": r["soft_404_control"][:20],
        "counts": {k: int(r["summary"].get(k, 0)) for k in ("pass", "fail", "gap", "skipped")},
        "findings": [row(c) for c in find[:6]],
        "findings_truncated": len(find) > 6,
        "passed": [c["id"][:50] for c in r["checks"] if c["verdict"] == "pass"][:14],
        "skipped": [{"id": c["id"][:32], "path": c["path"][:140], "reason": c["detail"][:120]}
                    for c in r["checks"] if c["verdict"] == "skipped"][:14],
        "summary": (f"{r['base_url']}: "
                    + ", ".join(f"{v} {k}" for k, v in sorted(r["summary"].items()))
                    + (". Origin unreachable." if r["origin_unreachable"] else ""))[:400],
    }
    # Hard cap. Trim findings detail, then findings, until it fits -- never emit an oversize payload.
    while len(json.dumps(p)) > cap and p["findings"]:
        if any(len(x["detail"]) > 160 for x in p["findings"]):
            for x in p["findings"]:
                x["detail"] = x["detail"][:160]
        elif p["skipped"]:
            p["skipped"] = p["skipped"][:-1]
        else:
            p["findings"] = p["findings"][:-1]
            p["findings_truncated"] = True
    return p


# --------------------------------------------------------------------------- selftest
def _selftest():
    fails = []
    J = {"Content-Type": "application/json"}

    class Fake(Fetcher):
        def __init__(self, pages, robots="", status=None):
            super().__init__("https://fake.test")
            self.allow_nonpublic = True
            self.pages, self._robots, self._status = pages, robots, status or {}

        def _raw(self, url, accept=""):
            self.n += 1
            p = urllib.parse.urlsplit(url).path or "/"
            if p == "/robots.txt":
                return (200, self._robots.encode(), {"Content-Type": "text/plain"}, None) \
                    if self._robots else (404, b"", {}, None)
            if p in self._status:
                st = self._status[p]
                if st in (429, 503):
                    self.blocked = True
                return st, b"", {}, None
            if p in self.pages:
                b, h = self.pages[p]
                h = dict(h); h["_final_url"] = url
                return 200, b, h, None
            return 404, b"", {}, None

    def V(r):
        return {c["id"]: c for c in r["checks"]}

    card = {"name": "x", "description": "d", "url": "https://fake.test/a2a", "version": "1",
            "skills": [{"id": "s"}]}
    r = audit("https://fake.test", Fake({"/.well-known/agent-card.json": (json.dumps(card).encode(), J)}))
    g = V(r)
    if g["agent_card"]["verdict"] != "pass":
        fails.append(f"clean card should pass: {g['agent_card']['detail']}")
    if g["soft404"]["verdict"] != "pass":
        fails.append("soft404 control should pass on a 404ing origin")
    if g["llms_txt"]["verdict"] != "gap":
        fails.append("absent llms.txt must be a gap")
    if "convention only" not in g["llms_txt"]["detail"]:
        fails.append("a gap with no measured demand must say so (M13)")
    if "346 requests" not in V(audit("https://fake.test", Fake({})))["agent_card"]["detail"]:
        fails.append("a gap WITH measured demand must cite it")
    if g["robots"]["verdict"] != "pass" or "valid and unrestrictive" not in g["robots"]["detail"]:
        fails.append("a missing robots.txt must not be a gap (M13)")

    # soft-404 origin: nothing may read as present OR absent
    class AllOk(Fake):
        def _raw(self, url, accept=""):
            self.n += 1
            if urllib.parse.urlsplit(url).path == "/robots.txt":
                return 404, b"", {}, None
            return 200, b"<html>nope</html>", {"Content-Type": "text/html", "_final_url": url}, None
    g2 = V(audit("https://fake.test", AllOk({})))
    if g2["soft404"]["verdict"] != "fail":
        fails.append("soft-404 origin must fail the control")
    if g2["agent_card"]["verdict"] != "skipped":
        fails.append(f"under a soft 404 nothing is present or absent, got {g2['agent_card']['verdict']}")

    # digest mismatch / match
    art = b"# skill body\n"
    bad_idx = {"skills": [{"id": "a", "url": "/s/a.md", "digest": "sha256:" + "0" * 64}]}
    good_idx = {"skills": [{"id": "a", "url": "/s/a.md",
                            "digest": "sha256:" + hashlib.sha256(art).hexdigest()}]}
    for idx, want in ((bad_idx, "fail"), (good_idx, "pass")):
        gg = V(audit("https://fake.test", Fake({
            "/.well-known/agent-skills/index.json": (json.dumps(idx).encode(), J),
            "/s/a.md": (art, {"Content-Type": "text/markdown"})})))
        if gg["skills_digests"]["verdict"] != want:
            fails.append(f"digest check expected {want}, got {gg['skills_digests']['verdict']}")

    # robots Disallow obeyed, incl. a full-URL artifact path (M3)
    g3 = V(audit("https://fake.test", Fake({}, robots="User-agent: *\nDisallow: /.well-known/\n")))
    if g3["agent_card"]["verdict"] != "skipped":
        fails.append("a robots Disallow must skip, not fetch")
    fx = Fake({}, robots="User-agent: *\nDisallow: /s/\n"); fx.load_robots()
    if fx.allowed("/s/a.md") or fx.get("https://fake.test/s/a.md")[0] != "ROBOTS":
        fails.append("robots must be applied to a full-URL fetch too (M3)")
    # Allow longest-match beats a broader Disallow
    fa = Fake({}, robots="User-agent: *\nDisallow: /\nAllow: /.well-known/\n"); fa.load_robots()
    if not fa.allowed("/.well-known/agent-card.json") or fa.allowed("/other"):
        fails.append("Allow longest-match not honoured (M11)")
    # a Disallow: / under a LATER group must not be attributed to GPTBot (M11)
    fb = Fake({}, robots="User-agent: GPTBot\nDisallow: /private/\n\nUser-agent: *\nDisallow: /\n"); fb.load_robots()
    if fb.blocks_ai_crawlers():
        fails.append("AI-crawler block mis-attributed across groups (M11)")
    fc = Fake({}, robots="User-agent: GPTBot\nUser-agent: CCBot\nDisallow: /\n"); fc.load_robots()
    if fc.blocks_ai_crawlers() != ["ccbot", "gptbot"]:
        fails.append(f"multi-UA group not accumulated (M11): {fc.blocks_ai_crawlers()}")

    # shift 365 (critic BLOCKER 1): a non-sha256 declared digest must NOT be compared, and must
    # never be reported in sha256 wording.
    body_b = b"hello"
    import hashlib as _h
    good = _h.sha256(body_b).hexdigest()
    for declared, want_fail in ((good, False), ("sha256:" + good, False),
                                ("sha512:" + "a" * 128, False), ("deadbeef", False)):
        idx = {"skills": [{"id": "a", "url": "/a.txt", "digest": declared}]}
        dd = V(audit("https://fake.test", Fake({
            "/.well-known/agent-skills/index.json": (json.dumps(idx).encode(), J),
            "/a.txt": (body_b, {"Content-Type": "text/plain"})})))["skills_digests"]
        if (dd["verdict"] == "fail") != want_fail:
            fails.append(f"digest {declared[:18]!r} graded {dd['verdict']}, expected "
                         f"{'fail' if want_fail else 'not fail'}: {dd['detail'][:120]}")
        if declared.startswith("sha512") and "declared sha256" in dd["detail"]:
            fails.append("a sha512 declaration must not be reported in sha256 wording")
    idx_bad = {"skills": [{"id": "a", "url": "/a.txt", "digest": "f" * 64}]}
    dbad = V(audit("https://fake.test", Fake({
        "/.well-known/agent-skills/index.json": (json.dumps(idx_bad).encode(), J),
        "/a.txt": (body_b, {"Content-Type": "text/plain"})})))["skills_digests"]
    if dbad["verdict"] != "fail" or "index entr(ies) examined" not in dbad["detail"]:
        fails.append(f"a real sha256 mismatch must fail AND state the scope: {dbad}")

    # shift 365 (critic BLOCKER 2): wildcard and end-anchored robots patterns must bind.
    fw = Fake({}, robots=("User-agent: *\nDisallow: /*/endpoints\nDisallow: /*.json$\n"
                          "Disallow: /*?*sort=\nAllow: /.well-known/agent-card.json\n"))
    fw.load_robots()
    for blocked in ("/mcp/x/endpoints", "/a.json", "/list?x=1&sort=new"):
        if fw.allowed(blocked):
            fails.append(f"robots wildcard pattern not honoured: {blocked} should be disallowed")
    if not fw.allowed("/.well-known/agent-card.json"):
        fails.append("a longer Allow must beat a shorter wildcard Disallow")
    if not fw.allowed("/a.jsonx"):
        fails.append("a `$`-anchored pattern must not match beyond the end")
    fs = Fake({}, robots="User-agent: *\nDisallow: /*\n"); fs.load_robots()
    if fs.allowed("/anything"):
        fails.append("`Disallow: /*` must block everything")
    fu = Fake({}, robots="User-agent: quietforge-discovery-audit/1.0\nDisallow: /\n")
    fu.load_robots()
    if fu.allowed("/x"):
        fails.append("a rule naming our UA with its version suffix must bind")
    fg = Fake({}, robots="User-agent: GPTBot\nDisallow: /*\n"); fg.load_robots()
    if fg.blocks_ai_crawlers() != ["gptbot"]:
        fails.append(f"`Disallow: /*` is a blanket AI-crawler block: {fg.blocks_ai_crawlers()}")

    # card.url on another host
    d6 = V(audit("https://fake.test", Fake({"/.well-known/agent-card.json": (
        json.dumps(dict(card, url="https://elsewhere.example/a2a")).encode(), J)})))["agent_card"]
    if d6["verdict"] != "fail" or "not the host" not in d6["detail"]:
        fails.append("card.url pointing at another host must fail")

    # v1.0 card without `url` must pass; a card with no endpoint must fail
    v1 = {"name": "x", "description": "d", "version": "1", "skills": [{"id": "s"}],
          "supportedInterfaces": [{"url": "https://fake.test/a2a", "transport": "JSONRPC"}],
          "capabilities": {"extensions": []}}
    d7 = V(audit("https://fake.test", Fake({"/.well-known/agent-card.json": (
        json.dumps(v1).encode(), J)})))["agent_card"]
    if d7["verdict"] != "pass" or not d7.get("notes"):
        fails.append(f"v1.0 card without url must pass with a note, got {d7['verdict']}")
    d8 = V(audit("https://fake.test", Fake({"/.well-known/agent-card.json": (
        json.dumps({"name": "x", "description": "d", "version": "1",
                    "skills": [{"id": "s"}]}).encode(), J)})))["agent_card"]
    if d8["verdict"] != "fail" or "no endpoint declared" not in d8["detail"]:
        fails.append("a card declaring no endpoint must fail")

    # non-A2A manifest at the alias path is not drift
    d9 = V(audit("https://fake.test", Fake({
        "/.well-known/agent-card.json": (json.dumps(card).encode(), J),
        "/.well-known/agent.json": (json.dumps({"display_name": "x", "payments": {}}).encode(), J)
    })))["agent_card_alias"]
    if d9["verdict"] != "pass" or "not an AgentCard shape" not in d9["detail"]:
        fails.append("a non-A2A agent.json must not read as drift")

    # shift 365: alias drift must be DESCRIBED, never called stale. A strict superset that keeps the
    # same name+version is an extension (pass + the added keys named); a changed value is a fail.
    d9b = V(audit("https://fake.test", Fake({
        "/.well-known/agent-card.json": (json.dumps(card).encode(), J),
        "/.well-known/agent.json": (json.dumps(dict(card, pricing={}, links=[])).encode(), J),
    })))["agent_card_alias"]
    if d9b["verdict"] != "pass" or "strict superset" not in d9b["detail"] \
            or "links, pricing" not in d9b["detail"]:
        fails.append(f"superset alias must pass and name the added keys, got {d9b}")
    if "stale" in d9b["detail"]:
        fails.append("the alias check must not assert staleness it cannot observe")
    d9c = V(audit("https://fake.test", Fake({
        "/.well-known/agent-card.json": (json.dumps(card).encode(), J),
        "/.well-known/agent.json": (json.dumps(dict(card, version="9.9.9")).encode(), J),
    })))["agent_card_alias"]
    if d9c["verdict"] != "fail" or "same key, different value: version" not in d9c["detail"]:
        fails.append(f"a changed value at the alias must fail and name the key, got {d9c}")
    # a NESTED addition is an extension, not drift (the shape seen in the wild)
    withcaps = dict(card, capabilities={"streaming": False, "extensions": []})
    nested = dict(withcaps, capabilities=dict(withcaps["capabilities"],
                                              stateTransitionHistory=False))
    d9d = V(audit("https://fake.test", Fake({
        "/.well-known/agent-card.json": (json.dumps(withcaps).encode(), J),
        "/.well-known/agent.json": (json.dumps(nested).encode(), J),
    })))["agent_card_alias"]
    if d9d["verdict"] != "pass" or "extra nested keys under: capabilities" not in d9d["detail"]:
        fails.append(f"a nested-only addition at the alias must pass, got {d9d}")
    # a nested key the alias DROPS is a conflict and must be named at its leaf path
    dropped = dict(withcaps, capabilities={k: v for k, v in withcaps["capabilities"].items()
                                           if k != "extensions"})
    d9e = V(audit("https://fake.test", Fake({
        "/.well-known/agent-card.json": (json.dumps(withcaps).encode(), J),
        "/.well-known/agent.json": (json.dumps(dropped).encode(), J),
    })))["agent_card_alias"]
    if d9e["verdict"] != "fail" or "capabilities.extensions (absent in the alias)" not in d9e["detail"]:
        fails.append(f"a nested key dropped by the alias must fail at its leaf path, got {d9e}")

    # M4: 403 / 429 must never read as absent
    d10 = V(audit("https://fake.test", Fake({}, status={"/.well-known/agent-card.json": 403})))
    if d10["agent_card"]["verdict"] != "skipped":
        fails.append(f"a 403 must be skipped, not a gap, got {d10['agent_card']['verdict']}")

    # shift 365: a refused PROBE leaves the soft-404 control unproven -- never a pass, and never
    # printed as "correctly returns 403". A bot-walled origin's only pass in a 13-origin census was this.
    d10b = V(audit("https://fake.test", Fake({}, status={
        "/.well-known/__qf_audit_probe_7f3a91": 403})))["soft404"]
    if d10b["verdict"] != "skipped" or "UNPROVEN" not in d10b["detail"]:
        fails.append(f"a refused soft-404 probe must be skipped as unproven, got {d10b}")
    if "correctly returns" in d10b["detail"]:
        fails.append("a refused probe must not be described as correctly returning anything")
    # critic BLOCKER 1: the SUMMARY field must not say "pass" when the probe was refused.
    r10b = audit("https://fake.test", Fake({}, status={
        "/.well-known/__qf_audit_probe_7f3a91": 403}))
    if r10b["soft_404_control"] != "unproven":
        fails.append(f"soft_404_control must read 'unproven' on a refused probe, "
                     f"got {r10b['soft_404_control']!r}")
    if "soft-404 control: unproven" not in to_payload(r10b)["method"]:
        fails.append("to_payload's method string must carry the unproven soft-404 control")

    # shift 365: with the canonical card absent, the alias must NOT be called identical to it.
    d10c = V(audit("https://fake.test", Fake({"/.well-known/agent.json": (
        json.dumps(card).encode(), J)})))["agent_card_alias"]
    if d10c["verdict"] != "pass" or "NOT readable" not in d10c["detail"] \
            or "identical" in d10c["detail"]:
        fails.append(f"alias with no canonical card must not claim identity, got {d10c}")
    r11 = audit("https://fake.test", Fake({}, status={
        "/.well-known/__qf_audit_probe_7f3a91": 429}))
    if not r11["rate_limited_by_origin"] or r11["requests_made"] > 3:
        fails.append(f"a 429 must stop the audit, made {r11['requests_made']} requests")

    # M4b: gzip sitemap must be skipped, not failed
    d12 = V(audit("https://fake.test", Fake({"/sitemap.xml": (
        b"\x1f\x8b\x08\x00junk", {"Content-Type": "application/gzip"})})))["sitemap"]
    if d12["verdict"] != "skipped" or "gzip" not in d12["detail"]:
        fails.append(f"a gzipped sitemap must be skipped, got {d12['verdict']}")
    d13 = V(audit("https://fake.test", Fake({"/sitemap.xml": (
        b"<html><body>hi</body></html>", {"Content-Type": "text/html"})})))["sitemap"]
    if d13["verdict"] != "skipped":
        fails.append(f"an HTML body at /sitemap.xml must be skipped, got {d13['verdict']}")

    # Shift 366 BLOCKER 1: a REFUSED sampled sitemap URL is UNPROVEN, never "does not resolve".
    sm_body = (b"<urlset><loc>https://fake.test/a</loc></urlset>")
    r403 = audit("https://fake.test", Fake({"/sitemap.xml": (sm_body, {"Content-Type": "application/xml"})},
                                           status={"/a": 403}))
    c403 = V(r403).get("sitemap", {})
    if c403.get("verdict") != "skipped" or "UNPROVEN" not in c403.get("detail", ""):
        fails.append(f"a 403 on a sampled sitemap URL must be skipped+UNPROVEN, got "
                     f"{c403.get('verdict')}: {c403.get('detail', '')[:80]}")
    if "do not resolve" in c403.get("detail", "") or "are absent" in c403.get("detail", ""):
        fails.append("a refused sampled URL must not be described as absent")
    # ...while a genuine 404 on a listed URL is still the origin's defect.
    r404 = audit("https://fake.test", Fake({"/sitemap.xml": (sm_body, {"Content-Type": "application/xml"})},
                                           status={"/a": 404}))
    if V(r404).get("sitemap", {}).get("verdict") != "fail":
        fails.append("a 404 on a sampled sitemap URL must still be a fail")

    # Shift 366 MAJOR 5: robots.txt 5xx = RFC 9309 complete disallow -> stop, issue nothing more.
    class Robots5xx(Fake):
        def _raw(self, url, accept=""):
            self.n += 1
            if (urllib.parse.urlsplit(url).path or "/") == "/robots.txt":
                return 503, b"", {}, None
            return 200, b"{}", {"Content-Type": "application/json", "_final_url": url}, None
    f5 = Robots5xx({})
    r5 = audit("https://fake.test", f5)
    if f5.n != 1:
        fails.append(f"a 5xx robots.txt must stop the audit after 1 request, issued {f5.n}")
    if not r5["origin_unreachable"] or V(r5).get("robots", {}).get("verdict") != "skipped":
        fails.append("a 5xx robots.txt must end the audit with robots=skipped")

    # M2: SSRF refusals
    ok, _ = host_is_public("localhost")
    ok2, _ = host_is_public("metadata.google.internal")
    if ok or ok2:
        fails.append("host_is_public must refuse localhost and *.internal")
    fh = Fake({})
    if fh.get("http://fake.test/x")[0] != "CROSSHOST" or \
            fh.get("https://evil.example/x")[0] != "CROSSHOST":
        fails.append("non-https and cross-host URLs must be refused (M2)")

    # M14: one check per skills index pair, ids unique
    rr = audit("https://fake.test", Fake({}))
    ids = [c["id"] for c in rr["checks"]]
    if len(ids) != len(set(ids)):
        fails.append(f"duplicate check ids: {[i for i in ids if ids.count(i) > 1]}")

    # M1/M12: the deliverable payload exists, conforms and respects the 8,000-char cap
    p = to_payload(rr)
    need = {"base_url", "checked_at", "method", "soft_404_control", "counts", "findings",
            "findings_truncated", "passed", "skipped", "summary"}
    if set(p) != need:
        fails.append(f"payload keys differ from the promised schema: {set(p) ^ need}")
    if sum(p["counts"].values()) != len(rr["checks"]):
        fails.append("counts must sum to the number of checks run")
    if len(json.dumps(p)) > PAYLOAD_CAP:
        fails.append("payload exceeds the 8,000-char cap")
    # a pathological result must still fit
    fat = dict(rr)
    fat["checks"] = [dict(c, id=f"c{i}", detail="x" * 900, repro="y" * 900, verdict="fail")
                     for i, c in enumerate(rr["checks"] * 3)]
    fat["summary"] = {"fail": len(fat["checks"])}
    pf = to_payload(fat)
    if len(json.dumps(pf)) > PAYLOAD_CAP or not pf["findings_truncated"]:
        fails.append(f"oversize result not bounded: {len(json.dumps(pf))} chars")

    # unreachable origin is a complete, honest delivery
    class Dead(Fake):
        def _raw(self, url, accept=""):
            self.n += 1
            return None, b"", {}, "URLError: dns"
    rd = audit("https://fake.test", Dead({}))
    pd = to_payload(rd)
    if pd["counts"]["gap"] or not pd["skipped"]:
        fails.append("an unreachable origin must produce skipped checks and zero gaps")

    # Shift 365: this was a hand-maintained literal (22) and had gone stale -- it still read 22
    # after 8 assertions were added, so the headline under-reported the suite. Derive it from the
    # number of assertion sites in this function instead, so it cannot drift again.
    with open(os.path.abspath(__file__)) as _f:
        _src = _f.read()
    # Only indented CALL sites, so this line's own literal is not counted (critic BLOCKER 3:
    # the anti-drift counter drifted by exactly one, itself).
    groups = len(re.findall(r"^\s+fails\.append\(", _src, re.M))
    print(f"selftest: {groups - len(fails)}/{groups} assertions ok")
    for x in fails:
        print("  FAIL", x)
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base")
    ap.add_argument("--json")
    ap.add_argument("--payload", action="store_true", help="print the deliverable payload")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--a2a-python", help="path to a Python with a2a-sdk installed, for the strict "
                                         "AgentCard protobuf parse (else QF_A2A_PYTHON, else the "
                                         "local venv; without one that check is reported skipped)")
    a = ap.parse_args()
    if getattr(a, "a2a_python", None):
        global VPY
        VPY = a.a2a_python
    if a.selftest:
        return _selftest()
    if not a.base:
        ap.error("--base is required (a public https:// origin)")
    if not a.base.startswith("https://"):
        ap.error("--base must be https://")
    ok, why = host_is_public(urllib.parse.urlsplit(a.base).netloc)
    if not ok:
        print(f"refused: {a.base} -> {why}")
        return 2
    r = audit(a.base)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(r, fh, indent=1)
    if a.payload:
        p = to_payload(r)
        print(json.dumps(p, indent=1))
        print(f"# payload {len(json.dumps(p))} chars (cap {PAYLOAD_CAP})", file=sys.stderr)
    elif not a.quiet:
        print(f"{r['base_url']}  {r['checked_at']}  requests={r['requests_made']}"
              f"/{r['request_budget']}  robots={r['robots_txt_status']}  "
              f"soft404_control={r['soft_404_control']}"
              + ("  RATE-LIMITED" if r["rate_limited_by_origin"] else ""))
        for c in r["checks"]:
            print(f"  [{c['verdict']:>7}] {c['id']:<18} {c['path']}")
            print(f"            {c['detail']}")
            for n in c.get("notes") or []:
                print(f"            note: {n}")
        print("  summary:", json.dumps(r["summary"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
