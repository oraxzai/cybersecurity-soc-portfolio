# Investigation Report: Synthetic Credential-Phishing Email

## Summary

On September 16, 2026, I examined a synthetic email designed to
imitate a credential-phishing attempt.

The message claimed to come from IT Support, threatened mailbox
disablement, and requested a work email address and password.

Analysis identified differing sender and reply domains, a mismatch
between the visible link and its destination, and language that
discouraged independent verification.

Assessment: Simulated credential-phishing attempt.

The email was created locally for training. No real delivery,
credential collection, or malware execution occurred.

## Objective

- Examine sender and reply-routing information.
- Identify the actual destination of an HTML link.
- Analyze social-engineering language.
- Inspect the supplied attachment content.
- Distinguish missing authentication evidence from failed checks.
- Produce an evidence-based verdict and recommended response.

## Evidence and Method

The original file was reviewed as text in Windows Notepad:

`01-training-phishing-email.eml`

The analysis used the email source rather than visiting its link
or rendering it in an email client.

Evidence consisted of:

- The original synthetic EML file.
- A screenshot of the headers.
- A screenshot of the HTML link.
- A screenshot of the message body.
- A screenshot of the attachment source.

All sender addresses, domains, and message metadata were constructed
training data. They were not independently verified delivery facts.

## Sender and Header Analysis

| Field | Observed value |
|---|---|
| Display name | IT Support |
| From address | helpdesk@company-support.test |
| Recipient | employee@company.test |
| Reply-To | account-review@external-mail.test |
| Subject | Urgent: Your mailbox will be disabled in 30 minutes |
| Date header | September 16, 2026, 10:00:00 +0000 |
| Message-ID | training-001@company-support.test |
| Training marker | X-Training-Sample: Synthetic SOC portfolio exercise |

### Findings

The recipient's domain was company.test, while the claimed sender
used company-support.test.

Replies were directed to a third domain, external-mail.test.

The display name "IT Support" did not verify the sender's identity.
A different sender or Reply-To domain can have a legitimate
explanation, so these differences were assessed with the other
message contents rather than treated as conclusive alone.

The Date header was part of the constructed sample. It did not
establish an actual sending or delivery time.

## Link Analysis

The HTML source contained:

```html
<a href="https://account-review.test/verify">https://mail.company.test</a>
```

| Component | Value |
|---|---|
| Visible link text | https://mail.company.test |
| Actual href destination | https://account-review.test/verify |
| Destination domain | account-review.test |
| Destination path | /verify |

The href attribute determines the link destination.
The visible text is only its label.

The link presented a company-mail address while pointing to a
different domain. Combined with the request for a password,
this supported the simulated phishing assessment.

The destination was not visited. No claim was made about the
content or behavior of a destination website.

## Social-Engineering Analysis

| Message content | Intended influence |
|---|---|
| Claims to be IT Support | Establish apparent authority |
| Mailbox disablement within 30 minutes | Create urgency and fear of losing access |
| Requests a work email and password | Encourage disclosure of credentials |
| Discourages help-desk contact | Reduce independent verification |

The assessment relied on the combination of these features,
not on urgency or a domain difference alone.

The email requested credentials, but the exercise did not
demonstrate credentials being submitted or collected.

## Attachment Analysis

The message contained a MIME attachment with these declared fields:

```text
Content-Type: text/plain; charset=UTF-8
Content-Disposition: attachment; filename="verification-instructions.txt"
```

Its source content was:

```text
SYNTHETIC TRAINING ATTACHMENT.
This is a harmless text file created for a SOC portfolio exercise.
No real credentials should be entered or collected.
```

### Finding

The inspected attachment part contained the harmless training
text shown above.

This conclusion was based on reviewing its contents, not merely
its .txt filename or declared content type.

No attachment execution, sandbox analysis, antivirus assessment,
or file-hash calculation was performed.

## Email Authentication and Delivery Evidence

A search of the source did not find an Authentication-Results header.

| Item | Assessment |
|---|---|
| SPF result | Not available |
| DKIM verification result | Not available |
| DMARC result | Not available |
| Received delivery chain | Not present in the synthetic sample |

The sample was created locally and was not delivered through
a mail system. Authentication outcomes could not be assessed.

Missing authentication results were not classified as failed checks.
Passing authentication would also not, by itself, establish that
an email's request was trustworthy.

No sending IP or delivery route was established.

## Extracted Investigation Details

| Type | Value |
|---|---|
| Claimed sender | helpdesk@company-support.test |
| Reply destination | account-review@external-mail.test |
| Recipient domain | company.test |
| Visible link domain | mail.company.test |
| Actual link domain | account-review.test |
| URL path | /verify |
| Attachment filename | verification-instructions.txt |

These are synthetic investigation details, not confirmed
real-world malicious indicators.

The domains use the .test namespace for training.

## Verdict

Classification: Simulated credential-phishing attempt.

Supporting observations:

1. The message claimed IT authority without independent verification.
2. Sender and reply-routing domains differed from the recipient's domain.
3. The visible link and actual destination did not match.
4. The message requested a work password.
5. Urgency and threatened account disablement pressured the recipient.
6. The message discouraged contacting the help desk.

The known construction of the sample and its contents supported
this training classification. No real compromise was demonstrated.

## Recommended Response for a Real Message

If a comparable message arrived at work:

1. Avoid replying, submitting credentials, or opening its links.
2. Preserve and report the original message through the approved process.
3. Verify the request using an independently known IT contact channel.
4. Have the security team review trusted mail-system logs,
   authentication results, and related messages.
5. Check whether the recipient interacted with the message.
6. If credentials were submitted, promptly notify IT so it can
   assess account recovery and session-revocation needs.

These are recommended actions for a real incident.
No real account containment was required in this exercise.

## Limitations

- The email was constructed for training, not obtained from a real campaign.
- Sender identities and message metadata were synthetic.
- No actual sending infrastructure or delivery route was investigated.
- SPF, DKIM, and DMARC results were unavailable.
- No URL destination was visited or analyzed.
- No external domain-reputation assessment was performed.
- The attachment was reviewed as source text only.
- No file hash, malware scan, or sandbox result was produced.
- No credential theft, execution, or account compromise occurred.
- No automated email detection rule was implemented.

## Original Evidence

[Download the synthetic email](evidence/01-training-phishing-email.eml)

Open the file as text to inspect the source.

## Screenshots

- [Header review](screenshots/01-email-header-review.png)
- [Visible link and destination mismatch](screenshots/02-link-destination-mismatch.png)
- [Social-engineering language](screenshots/03-email-social-engineering.png)
- [Attachment source review](screenshots/04-attachment-source-review.png)

## Lessons Learned

1. A familiar display name does not establish identity.
2. Examine From and Reply-To separately.
3. Read href to identify an HTML link's destination.
4. Assess multiple clues together.
5. Distinguish a request for credentials from observed credential theft.
6. Inspect attachment contents rather than trusting the filename.
7. Record unavailable authentication evidence as unavailable, not failed.
8. Verify requests through independently known contact channels.
