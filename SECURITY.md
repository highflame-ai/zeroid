# Security Policy
  
  We take security seriously. Please report vulnerabilities **privately** so we can
  fix them before disclosure.

  ## Reporting a vulnerability

  **Use GitHub's private vulnerability reporting:**
  https://github.com/highflame-ai/zeroid/security/advisories/new

  This routes the report to repository administrators only. Do not file a public
  issue for any vulnerability that has an exploit path — the issues tracker is
  public and indexed by search engines.

  If you cannot use the GitHub form, email **support@highflame.com** with:

  - A description of the issue
  - Steps to reproduce
  - Affected versions
  - Your name + contact for credit (optional)
  - A suggested fix or mitigation if you have one

  ## Scope
  
  In scope:
  - Auth bypass, IDOR, tenant-isolation violations
  - Token forgery, signature confusion, algorithm confusion
  - Privilege escalation, scope-ceiling bypasses
  - SSRF, SQLi, command injection
  - Secret exposure (logs, errors, telemetry)
  - DoS that's amplifiable beyond a single client

  Out of scope (please file public issues for these):
  - Documentation typos
  - Feature requests
  - Performance issues that aren't security-amplifiable
  - Self-DoS (e.g. "if I generate a 10GB JWT, the server slows down")

  ## Supported versions

  Security fixes ship to:
  - `main` (always)
  - The most recent tagged release (when versioned releases exist)
  
  ## Response SLA

  - Initial acknowledgement: **within 2 business days**
  - Triage decision (in scope / out of scope / severity): **within 5 business days**
  - Fix targeted: **within 30 days** for critical/high; **90 days** for medium; best-effort for low
  - Public disclosure (CVE): **after a fix is available** and customers have had reasonable time to update

  ## Process

  1. Reporter files a private report
  2. Highflame triages, drafts a GitHub Security Advisory
  3. Fix is developed in a temporary private fork (linked off the advisory)
  4. Once the fix lands on `main` and a release tag exists, the advisory is published as a CVE
  5. Reporter is credited (with permission)

  ## Credits
  
  We thank everyone who has reported issues responsibly. Confirmed reporters who
  opt in are listed in the published advisory and our release notes.
