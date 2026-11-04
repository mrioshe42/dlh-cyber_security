# MedDefense SAML SSO Configuration Reference

## Realm Configuration Summary
- **Realm:** `meddefense` | **Display Name:** MedDefense Health Systems
- **Session Idle Timeout:** 30 min (1800 sec) | **Brute Force:** 5 failed attempts → lockout
- Realm isolates users; single sign-out across all systems

## Client Configuration Summary
| Setting | Value |
|---|---|
| Client ID | meddefense-portal |
| Protocol | SAML 2.0 |
| ACS URL | http://localhost:5000/saml/acs |
| NameID Format | email (persistent workforce identifier) |
| Assertion Signing | Enabled (signed by Keycloak private key) |
| Document Signing | Enabled (response envelope also signed) |
| Attribute Mapper | MedDefenseRole (Basic format) |

## Test Users and Role Attributes
| Username | Email | Role |
|---|---|---|
| d.walsh | d.walsh@meddefense.internal | clinical_staff |
| r.kim | r.kim@meddefense.internal | it_security |

## Annotated SAML Assertion: d.walsh
```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp-dwalsh-20260428" Version="2.0" IssueInstant="2026-04-28T09:15:00Z" Destination="http://localhost:5000/saml/acs">
  <saml:Issuer>http://localhost:8080/realms/meddefense</saml:Issuer>
  <ds:Signature><ds:SignedInfo><ds:Reference URI="#_assert-dwalsh-001"/></ds:SignedInfo><ds:SignatureValue>SIMULATED_SIGNATURE_VALUE_FOR_LAB_ONLY</ds:SignatureValue></ds:Signature>
  <saml:Assertion ID="_assert-dwalsh-001" Version="2.0" IssueInstant="2026-04-28T09:15:00Z">
    <saml:Issuer>http://localhost:8080/realms/meddefense</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">d.walsh@meddefense.internal</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2026-04-28T09:20:00Z" Recipient="http://localhost:5000/saml/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-04-28T09:14:55Z" NotOnOrAfter="2026-04-28T09:20:00Z">
      <saml:AudienceRestriction><saml:Audience>meddefense-portal</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-04-28T09:14:58Z" SessionIndex="_session-dwalsh-001">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="MedDefenseRole"><saml:AttributeValue>clinical_staff</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="email"><saml:AttributeValue>d.walsh@meddefense.internal</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

**Key Elements:** Issuer (IdP identity), NameID (email for account lookup), Conditions (NotBefore/NotOnOrAfter validity window), Signature (tamper protection), AuthnStatement (auth event), AttributeStatement (MedDefenseRole + email for authorization)

## Assertion Expiration and Replay Prevention
Each assertion has two expiration constraints: **Conditions NotBefore/NotOnOrAfter** bounds the entire assertion; **SubjectConfirmationData NotOnOrAfter** expires the subject. The 5-second window (5–10 min in production) defeats replay—an attacker cannot reuse an expired assertion. SP clocks must sync with IdP (±1 min tolerance); if rejected as expired/not-yet-valid, user re-authenticates and Keycloak issues fresh timestamps.

## Assertion Signing Risk Explanation
**Signing goal:** Keycloak signs with its private key; SP verifies with public certificate. Prevents tampering (attacker cannot change `clinical_staff` → `admin` without breaking signature) and proves issuer identity.

**Risk:** Compromised private key = attacker forges arbitrary assertions as any user with any role. Centralized IdP becomes high-value target. **Mitigations:** hardened access controls, audit logging, HSM integration, regular patching, network segmentation, key rotation (annual or on security events).

## Off-Boarding and Centralized Identity Impact

**Before SSO:** Manual per-system disabling (Epic, PACS, pharmacy, comm platform). Incident: two departed employees had active Epic accounts because off-boarding ticket not propagated.

**After SSO:** Single action in Keycloak—disable user or set `enabled: false`—blocks all systems. Next login attempt fails: no valid SAML assertion. No stale accounts, single event, all systems sync automatically.

**Implementation:** Test users `d.walsh` and `r.kim` set `enabled: false` on departure → no valid assertion → all systems deny access immediately. Keycloak becomes authoritative identity source; off-boarding reduces overhead and security risk.
