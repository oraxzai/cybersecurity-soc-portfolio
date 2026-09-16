# Phishing Email Investigation

## Overview

Analyze a synthetic credential-phishing email using its original
source to examine sender details, link destinations, message
language, and attachment contents.

## Environment and Tools

- Windows VM in VMware Fusion.
- Windows Notepad for source inspection.
- Locally created EML training sample.
- Investigation date: September 16, 2026.

## Work Performed

- Compared the From, Reply-To, and recipient domains.
- Identified the actual href destination behind misleading link text.
- Examined urgency, authority claims, and requests for credentials.
- Reviewed a harmless text attachment directly in the MIME source.
- Checked for authentication and delivery evidence.
- Documented findings, limitations, and recommended response actions.

## Key Findings

- The claimed sender and reply destination used different domains
  from the recipient.
- The visible company-mail link pointed to another domain.
- The message requested a password and discouraged IT verification.
- The inspected attachment contained harmless training text.
- Authentication results and a delivery chain were unavailable.

Assessment: Simulated credential-phishing attempt.
No real delivery, credential collection, or compromise occurred.

## Investigation Report

[Read the full investigation report](investigation-report.md)

## Evidence

- [Original synthetic email](evidence/01-training-phishing-email.eml)
- [Analysis screenshots](screenshots/)

## Skills Demonstrated

- Email source and header inspection.
- Sender and reply-routing comparison.
- HTML link analysis.
- Social-engineering recognition.
- Basic MIME attachment inspection.
- Evidence-based assessment and response planning.

## Scope and Limitations

This was a synthetic source-analysis exercise, not a real
phishing incident.

No mail-server authentication validation, live URL analysis,
attachment execution, malware scanning, file hashing, or external
reputation assessment was performed.

The sample's addresses and domains are training details, not
confirmed real-world malicious indicators.

## Related Project

[DNS Investigation & Threat Hunting](../07-DNS-Investigation/)
