# Reference notes

Read-only. Nothing here is imported by `src/`, and nothing here is on the
build path.

Per the project rules: no code is copied from external projects. Where an idea
comes from somewhere, it is credited here.

## Sources credited so far

Nothing yet. Sprint 1 is written directly against
`docs/behavioral-firewall-spec.md`; the libraries used (`psutil`,
`cryptography`, `sqlite3`, `pytest`) are used through their public APIs only.

## Evaluated and deferred

### Flask hardening snippet (Talisman + Flask-Limiter)

A snippet was offered as a starting point for securing a Flask app. **Not
adopted, and no code taken from it.** The dashboard is Sprint 9 and may not be
Flask at all (spec 12 offers Textual as the alternative).

Recorded because the two *ideas* - security headers and per-route rate limiting -
are worth revisiting if the dashboard does end up being Flask, and because the
snippet's flaws are worth not repeating:

- `storage_uri="memory://"` - limits reset on restart and are not shared
  between worker processes, so N workers permit N times the intended rate.
  Needs a shared backend.
- `get_remote_address` with no `ProxyFix` - behind a reverse proxy every client
  is seen as the proxy, so they share one bucket; or `X-Forwarded-For` is
  spoofable. Trusted-proxy configuration is required.
- `force_https=False` with a comment to flip it before deploying - a protection
  that depends on remembering. It belongs in an environment variable.
- `app.run()` - the development server.

The first two are the same failure this project keeps finding: a protection
that appears to be in place and is not.

### WAF landscape survey (github.com/topics/waf, by stars)

Browsed on request. WAF integration is out of scope (spec 3) and listed only
under Future Work (spec 19); nothing here was adopted.

One finding bears on the roadmap rather than on the code:

**crowdsecurity/crowdsec** (14.9k stars, Go) - "open-source and participative
security solution offering crowdsourced protection against malicious IPs" - is
a direct incumbent for Appendix A idea 4, "supply-chain alerting: a shared
indicator between customers without revealing who was hit", which the appendix
describes as a growing competitive moat (network effect).

The moat is occupied. A local agent feeding a shared reputation pool already
exists at scale. The idea may still be worth pursuing, but not on the strength
of being first.

Also noted: the topic page is user-tagged and unreliable as a market survey -
it lists a Ruby web framework and two game engines among the WAFs.

For reference if the roadmap ever reaches WAF correlation: owasp-modsecurity/
ModSecurity (9.8k, C++), corazawaf/coraza (3.8k, Go, ModSecurity-compatible),
coreruleset/coreruleset (the OWASP CRS rule set).
