# Confused Deputy: LangGraph + ZeroID

This example demonstrates how ZeroID prevents the **Confused Deputy** problem (indirect prompt injection) in a multi-agent LangGraph workflow.

## The Vulnerability

In a standard multi-agent pipeline, an **Email Agent** reads an HR inbox and passes the contents to a **Payroll Agent** equipped with privileged HR system credentials. If an attacker sends an email containing a hidden `PAYROLL_COMMAND`, the Payroll Agent might implicitly trust its peer's output and execute the injected command—rerouting an employee's direct deposit to an attacker's account. This is Business Email Compromise (BEC) at AI speed.

## The Solution

ZeroID enforces cryptographically verifiable scope boundaries using **WIMSE** identities and **RFC 8693 token exchange**. The same Payroll Agent uses different tokens depending on the data source:

* **`[depth=0]` Payroll Agent (own token):** Full access (`email:read`, `payroll:read`, `payroll:write`). Used for verified internal requests — the payroll write **succeeds**.
* **`[depth=1]` Email Agent:** Delegated `email:read` only. Authenticates against the email API to read the inbox.
* **`[depth=2]` Payroll Agent (context token):** When processing Email Agent output, the Payroll Agent operates under the Email Agent's scope ceiling (`email:read` only). The injected payroll command is **rejected at the tool boundary**.

The LangGraph graph uses conditional routing to direct requests to the appropriate handler based on data source:

```
                  ┌─ payroll_direct (own token) ──┐
START → read_inbox┤                               ├→ END
                  └─ payroll_from_email (context) ─┘
```

The tool boundary enforces scope cryptographically — it doesn't matter that the LLM was tricked into executing the injected command. The token can't authorize the action.

> *ZeroID provides the tools to enforce scope attenuation and least privilege. Correct implementation in the graph logic is required.*

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
