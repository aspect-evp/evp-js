# Standards status and conformance

[Documentation home](README.md) · [Protocol flow](PROTOCOL-FLOW.md) · [Issuer](issuer.md) · [Verifier](verifier.md)

EVP is an emerging protocol, not a finished web standard. `evp-js` targets [draft-hardt-email-verification-00](https://www.ietf.org/archive/id/draft-hardt-email-verification-00.html) and does not treat browser experiments or open issue proposals as normative requirements.

## Conformance policy

The implementation follows these rules:

- Normative requirements in the current protocol draft are enforced by default.
- An implementation difference is documented rather than accepted silently.
- Compatibility behavior is added only after the governing specification changes, or through an explicit opt-in API that cannot be mistaken for standards conformance.
- `evp-js` does not claim to standardize browser behavior. Changes to Fetch destinations and browser APIs belong in their respective standards.

## Current requirements

The targeted protocol draft requires:

- `Sec-Fetch-Dest: email-verification` on issuance requests; and
- a non-empty `kid` in the EVT protected header, used to select the issuer key.

The issuer middleware therefore rejects `emailverification` and other destination values. The verifier rejects an EVT with a missing or empty `kid`.

## Open Fetch destination discrepancy

[WICG issue #45](https://github.com/WICG/email-verification/issues/45) reports that a Chromium prototype sends `Sec-Fetch-Dest: emailverification`, without the hyphen. The targeted protocol draft requires `email-verification`. At the time this guide was written, the Fetch Standard registered neither value as a request destination.

This is an unresolved standards question, not a condition the library can settle by accepting both spellings. `evp-js` remains strict to the current protocol text until the relevant specifications converge.

## Assurance provided

A successful verification means that the email domain delegated to the issuer, the issuer signed the EVT, and the presentation passed the protocol's signature, claim, audience, nonce, timestamp, and key-binding checks.

It does not by itself prove mailbox deliverability, classify spam or disposable domains, guarantee fresh mailbox access, or replace application authentication, recovery, session, and abuse policy.

## Reporting implementation results

Reports to the standards repository should distinguish among:

- a requirement written in a specification;
- behavior observed in a named browser build; and
- behavior implemented by this library.

Include a reproducible test and exact version when claiming observed browser behavior. Do not state that a browser was tested unless that test was actually performed.
