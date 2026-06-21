#  E-Commerce Platform

### System Overview

**Frontend:** React | **Backend:** Node.js API | **Database:** PostgreSQL | **Payments:** Stripe

```
User Flows:
├─ Browse Products (no auth)
├─ Add to Cart (no auth)
├─ Checkout & Pay (auth required)
└─ View Order History (auth required)
```

## Q1: Three STRIDE Threats for Checkout

### Threat #1: **Tampering** - Price Manipulation

| Aspect | Details |
|--------|---------|
| **Category** | **TAMPERING** |
| **Description** | Attacker modifies product price in frontend before submitting payment |
| **Attack Scenario** | User opens browser DevTools, changes `$99.99` → `$9.99` in HTML/JavaScript, then completes purchase |
| **Impact** | Direct revenue loss; unauthorized price discounts |
| **Likelihood** | **VERY HIGH** - trivially easy to execute |
| **Mitigation** | **Never trust frontend prices** - Always validate prices server-side before payment; Calculate totals on backend only; Hash/sign price data |

---

### Threat #2: **Information Disclosure** - Payment Data Interception

| Aspect | Details |
|--------|---------|
| **Category** | **INFORMATION DISCLOSURE** |
| **Description** | Attacker intercepts unencrypted payment credentials during transmission |
| **Attack Scenario** | Man-in-the-middle attack on insecure connection; attacker captures credit card data in network traffic |
| **Impact** | Credit card fraud; regulatory breach (PCI-DSS); customer trust loss |
| **Likelihood** | **MEDIUM-HIGH** - if HTTPS not enforced |
| **Mitigation** | **Enforce HTTPS/TLS** on all payment endpoints; Never log/store full card numbers; Use Stripe tokenization (never handle raw payment data); Implement HSTS headers |

---

### Threat #3: **Spoofing** - Fraudulent User Identity

| Aspect | Details |
|--------|---------|
| **Category** | **SPOOFING** |
| **Description** | Attacker uses stolen credentials or session token to purchase with another user's account |
| **Attack Scenario** | Attacker steals session cookie; makes purchases without authorization using victim's payment method & shipping address |
| **Impact** | Unauthorized transactions; customer financial loss; account takeover |
| **Likelihood** | **MEDIUM** - depends on session management strength |
| **Mitigation** | **Implement MFA** at checkout; Session tokens: short-lived + httpOnly + Secure flags; IP-based anomaly detection; Transaction confirmation emails |

---

## Q2: Trust Boundaries

### Boundary Map

```
┌─────────────────────────────────────────────────────┐
│  UNTRUSTED ZONE (User Control)                      │
│  ┌──────────────────────────────────────────────┐   │
│  │  React Frontend (Browser)                    │   │
│  │  - User input validation (easy to bypass)    │   │
│  │  - Price/Quantity in DOM                     │   │
│  └────────────┬─────────────────────────────────┘   │
└───────────────┼─────────────────────────────────────┘
                │ TRUST BOUNDARY #1
                │ HTTP/HTTPS Request
                ↓
┌───────────────────────────────────────────────────────┐
│  SEMI-TRUSTED ZONE (Server, But Verify Everything)    │
│  ┌──────────────────────────────────────────────────┐ │
│  │  Node.js API Backend                             │ │
│  │  - Validates all inputs                          │ │
│  │  - Authentication checks                         │ │
│  │  - Price recalculation                           │ │
│  └───────────────────┬──────────────────────────────┘ │
└──────────────────────┼────────────────────────────────┘
                       │ TRUST BOUNDARY #2
                       │ SQL Queries
                       ↓
┌───────────────────────────────────────────────────────┐
│  TRUSTED ZONE (Protected Database)                    │
│  ┌──────────────────────────────────────────────────┐ │
│  │  PostgreSQL Database                             │ │
│  │  - Parameterized queries (SQL injection defense) │ │
│  │  - Encrypted sensitive data                      │ │
│  │  - Access controls                               │ │
│  └──────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────┘
                       │ TRUST BOUNDARY #3
                       │ Stripe API Call (External)
                       ↓
              Stripe Payment Service
```

### Three Key Trust Boundaries:

| # | Boundary | Data Crossing | Risk |
|---|----------|---------------|------|
| **1** | Browser → Backend | HTTP Request (cart items, prices, user input) | **HIGH** - Attacker controls frontend |
| **2** | Backend → Database | SQL Queries (sensitive customer data) | **HIGH** - SQL injection risk |
| **3** | Backend → Stripe API | Payment tokens & transaction data | **MEDIUM** - Encrypted but critical |

---

## Q3: DREAD Score for SQL Injection in Product Search

### Attack Scenario
```
User input: search?q='; DROP TABLE products; --
Backend query: SELECT * FROM products WHERE name LIKE '%...%'
Result: Without parameterized queries → Database compromised
```

### DREAD Scoring Breakdown

| Factor | Score | Justification |
|--------|:-----:|---------------|
| **D - Damage Potential** | **8/10** | Full database compromise (product catalog, customer data, orders) = maximum impact |
| **R - Reproducibility** | **10/10** | Trivial to execute (basic string injection in search bar) = 100% reproducible |
| **E - Exploitability** | **9/10** | Requires minimal skill (basic SQL knowledge), automated tools available = very easy |
| **A - Affected Users** | **10/10** | All users who search = entire user base impacted if exploited |
| **D - Discoverability** | **9/10** | Search functionality is public & obvious attack vector = easily found |

### **DREAD Total Score**

```
(8 + 10 + 9 + 10 + 9) ÷ 5 = 46 ÷ 5 = 9.2/10
```

### **Risk Rating: CRITICAL (8.0-10.0)**

---

## Key Mitigations (Priority Order)

| Priority | Mitigation | Impact |
|----------|-----------|--------|
| **P0** | Use **parameterized queries** in Node.js (e.g., `db.query('SELECT * FROM products WHERE name LIKE ?', [searchTerm])`) | Eliminates SQL injection risk entirely |
| **P0** | Implement **server-side input validation** & sanitization | Prevents malicious input from reaching database |
| **P1** | **Principle of Least Privilege** - API should only SELECT, never have DROP/DELETE permissions | Limits damage if injection occurs |
| **P1** | **Web Application Firewall (WAF)** to detect/block SQL patterns | Defense-in-depth layer |
