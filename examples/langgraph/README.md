# Confused Deputy: LangGraph + ZeroID

This example demonstrates how ZeroID prevents the **Confused Deputy** problem (indirect prompt injection) in a multi-agent LangGraph workflow.

## The Vulnerability

In a standard two-agent pipeline, an **Email Agent** reads an HR inbox and passes the contents to a **Payroll Agent** equipped with privileged HR system credentials.

If an attacker sends an email containing a hidden `PAYROLL_COMMAND`, the Payroll Agent might implicitly trust its peer's output and execute the injected command—such as rerouting an employee's direct deposit to an attacker's account. This is Business Email Compromise (BEC) at AI speed, caused by a lack of identity boundaries between agents.

## The Solution

ZeroID prevents this by enforcing strict, cryptographically verifiable scope boundaries using **WIMSE (Workload Identity in Multi-Service Environments)** identities. It utilizes an **RFC 8693 3-hop delegation chain** to ensure the Payroll Agent is securely constrained when processing untrusted content.

Instead of a single shared credential, tokens are attenuated (scoped down) at every handoff:

* **`[depth=0]` Payroll Agent:** Starts with full access (`email:read`, `payroll:read`, `payroll:write`). It delegates *only* `email:read` to the Email Agent.
* **`[depth=1]` Email Agent:** Operates strictly with `email:read`. It processes the inbox and passes the output back to the Payroll Agent, delegating its restricted scope.
* **`[depth=2]` Payroll Agent (Context Token):** The LangGraph workflow is designed so that the Payroll Agent **operates under this restricted context token** when processing the Email Agent's output. It now operates under the Email Agent's limited scope (`email:read`).



If the injected prompt tricks the Payroll Agent into calling a privileged payroll tool, the tool verifies the active token. Because the `depth=2` context token lacks the `payroll:write` permission, the malicious action is **rejected at the tool boundary**—enforced by cryptography, not AI reasoning. 

> *ZeroID provides the professional-grade tools to design secure workflows that enforce scope attenuation and least privilege, but correct implementation in the graph logic is required.*

## Quickstart

**1. Start ZeroID (from the repository root):**
```bash
make setup-keys && docker compose up -d
```
**2. Install dependencies:**
```bash
pip install highflame langgraph 'PyJWT[cryptography]'
```
**3. Run the example:**
```bash
export ZEROID_BASE_URL=http://localhost:8899
export ZEROID_ADMIN_API_KEY=zid_sk_... # Replace with your actual admin key
python confused_deputy.py
```
