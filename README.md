# URL Safety Checker — Version 1

A lightweight, fully static URL safety checker that runs entirely in the browser. No backend required. Deployed on GitHub Pages.

## Live Demo

[https://tien-bap.github.io/url-safety-checker](https://tien-bap.github.io/url-safety-checker)

---

## Architecture

The system uses a 3-layer pipeline to evaluate URLs:

```
URL Input
    │
    ▼
Layer 1: Hash-based Blacklist Lookup
    │   MATCH → DANGEROUS
    ▼
Layer 2: Static Analysis (Rule-based)
    │   FLAGS FOUND → SUSPICIOUS/DANGEROUS
    ▼
Layer 3: Machine Learning (LightGBM via ONNX)
    └── Output: Phishing probability
```

All three layers run client-side in the browser using JavaScript. No data is sent to any server.

---

## Layer 1 — Hash-based Blacklist

### Data Sources

| Source | Type | URLs |
|---|---|---|
| URLhaus (abuse.ch) | Malware URLs | ~61,000 |
| OpenPhish | Phishing URLs | ~300 |

### Mechanism

URLs from each source are normalized, SHA-256 hashed, and stored in a bucket map keyed by the first 8 hex characters of the hash (prefix). This allows O(1) lookup without exposing the original URLs.

```
URL → SHA-256 → prefix (8 chars) → bucket lookup → full hash match
```

The `hashes.json` file is automatically updated every 12 hours via GitHub Actions, which downloads the latest feeds, hashes all URLs, and commits the updated file to the repository.

### Structure of hashes.json

```json
{
  "a3f9bc12": ["a3f9bc12ef34...(full 64-char hash)", ...],
  "ff00ee11": ["ff00ee112233..."]
}
```

---

## Layer 2 — Static Analysis

A rule-based analysis of the URL string without making any network requests. Features are extracted from the URL structure and evaluated against a set of heuristic rules.

### Feature Groups

**Lexical**
- URL length (suspicious if > 100 chars excluding query string)
- Number of dashes in domain (suspicious if ≥ 4)
- Number of subdomains (suspicious if > 2)
- Encoded character count in path (suspicious if > 5)

**Domain Pattern**
- IP address used instead of domain name
- Suspicious TLDs: `.tk .ml .ga .cf .gq .xyz .top .club .sbs .cfd .click .casa .vip .love .ink .lk .cn .ru .bz`
- Brand name in subdomain (e.g. `paypal.evil.com`)
- Brand impersonation via country TLD (e.g. `roblox.com.ml`)
- Suspicious keywords in domain: `login secure verify update confirm signin`
- Repeated characters suggesting typosquatting (e.g. `liivee`, `robiox`)
- Purely numeric domain (e.g. `135461223.site`)
- Long consonant sequences suggesting random/generated domain

**Platform**
- Random-looking domain hosted on free platforms: `pages.dev vercel.app replit.app netlify.app github.io blogspot.com workers.dev`

**Structure**
- HTTP instead of HTTPS
- `@` character in URL (browser ignores everything before `@`)
- Non-standard port
- Double slash in path
- Open redirect parameters: `url= redirect= next= goto=`

**Trusted TLD Whitelist**
- `.edu.vn .gov.vn .edu .gov .ac.uk .ac.jp` — skip static analysis entirely

---

## Layer 3 — Machine Learning

### Model

**Algorithm:** LightGBM (Gradient Boosting Decision Tree)
**Export format:** ONNX (runs in browser via onnxruntime-web)
**Input:** 35 features extracted from the URL string
**Output:** Binary classification — `0 = Phishing`, `1 = Safe`

### Training Dataset

| Source | Label | Count |
|---|---|---|
| PhiUSIIL Phishing URL Dataset (2023) | Mixed | 235,795 |
| URLhaus + OpenPhish (blacklist) | Phishing (0) | 60,954 |
| Tranco Top 1M domains | Safe (1) | 60,954 |
| **Total** | | **357,703** |

Label distribution: 54.7% Safe / 45.3% Phishing

### Feature List (35 features)

| Group | Features |
|---|---|
| Lexical | URLLength, DomainLength, IsDomainIP, TLDLength, NoOfSubDomain, NoOfLettersInURL, LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL, NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL, NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL, IsHTTPS |
| Entropy | Entropy (Shannon entropy of URL characters) |
| Obfuscation | HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio |
| Keyword | Bank, Pay, Crypto, HasSuspiciousWord |
| Domain Pattern | HasSuspiciousTLD, DomainDashCount, HasRepeatedChars, IsNumericDomain, BrandInSubdomain, BrandDotCom, ConsonantGroups, IsOnSuspiciousPlatform |
| Structure | HasAt, HasPort, HasDoubleSlash, HasRedirectParam |

### Evaluation Results

**5-Fold Stratified Cross-Validation**

| Metric | Mean | Std |
|---|---|---|
| Accuracy | 0.9971 | ±0.0002 |
| Precision (macro) | 0.9973 | ±0.0002 |
| Recall (macro) | 0.9969 | ±0.0002 |
| F1 (macro) | 0.9971 | ±0.0002 |
| ROC AUC | 0.9988 | ±0.0002 |

**Confusion Matrix (test set, 20%)**

| | Predicted Safe | Predicted Phishing |
|---|---|---|
| Actual Safe | 32,216 | 164 |
| Actual Phishing | 24 | 39,137 |

ROC AUC Score: **0.9990**

**Top Feature Importances**

| Feature | Importance |
|---|---|
| URLLength | 18.44% |
| DomainLength | 10.33% |
| LetterRatioInURL | 10.32% |
| Entropy | 9.43% |
| DomainDashCount | 8.89% |
| SpacialCharRatioInURL | 8.62% |
| NoOfSubDomain | 7.65% |
| TLDLength | 6.56% |
| HasRepeatedChars | 4.70% |
| HasSuspiciousTLD | 2.70% |

---

## Automatic Blacklist Updates

A GitHub Actions workflow runs every 12 hours to refresh the blacklist:

1. Download latest feeds from URLhaus and OpenPhish
2. Normalize and SHA-256 hash all URLs
3. Build prefix bucket map
4. Commit updated `hashes.json` to repository
5. GitHub Pages automatically serves the new file

---

## Limitations

- **Blacklist coverage:** Only ~61k known malicious URLs. Brand new phishing URLs will not be detected by Layer 1.
- **Static analysis false positives:** Legitimate URLs with complex query strings (e.g. SSO/SAML) may trigger rules. Trusted TLD whitelist partially mitigates this.
- **No network checks:** Domain age (WHOIS), SSL certificate validation, and real-time reputation lookups are not available in the static version.
- **ML generalization:** Model trained primarily on 2023 data. Novel phishing techniques may reduce effectiveness over time.

---

## Tech Stack

| Component | Technology |
|---|---|
| Hosting | GitHub Pages |
| Blacklist update | GitHub Actions |
| Hashing | CryptoJS (SHA-256) |
| ML inference | onnxruntime-web |
| ML training | LightGBM + scikit-learn (Python) |
| ONNX export | onnxmltools + skl2onnx |
| Data sources | URLhaus, OpenPhish, PhiUSIIL, Tranco |

---

## Version 2 (Coming)

A local Python version with:
- Google Safe Browsing API (hundreds of millions of URLs)
- WHOIS domain age lookup
- SSL certificate validation
- Full LightGBM model (no ONNX conversion needed)
