# Detection Methodology

## SPF Failure Detection

### Description

Sender Policy Framework (SPF) verifies whether an email was sent from an authorised mail server.

### Detection Logic

If SPF result equals:

```text
fail
```

the message is considered suspicious.

### Reason

Attackers frequently spoof sender domains.

---

## DKIM Failure Detection

### Description

DomainKeys Identified Mail (DKIM) validates message integrity.

### Detection Logic

If DKIM validation fails:

```text
dkim=fail
```

additional risk points are assigned.

---

## DMARC Failure Detection

### Description

DMARC verifies alignment between SPF, DKIM, and sender domains.

### Reason

DMARC failures are common indicators of spoofed emails.

---

## Reply-To Mismatch Detection

Example:

```text
From: microsoft.com
Reply-To: evil-login.xyz
```

This may indicate redirection to an attacker-controlled mailbox.

---

## Credential Harvesting Detection

Examples:

* Verify your account
* Enter your password
* Confirm your credentials

These phrases are commonly observed in phishing campaigns.
