import onnxruntime as rt
import numpy as np
import re
import pandas as pd
import math
from urllib.parse import urlparse

FEATURE_NAMES = [
    # Lexical cơ bản
    'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength',
    'NoOfSubDomain', 'NoOfLettersInURL', 'LetterRatioInURL',
    'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL',
    'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL',
    'SpacialCharRatioInURL', 'IsHTTPS',

    # Entropy
    'Entropy',

    # Obfuscation
    'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio',

    # Keyword
    'Bank', 'Pay', 'Crypto', 'HasSuspiciousWord',

    # Domain pattern
    'HasSuspiciousTLD', 'DomainDashCount', 'HasRepeatedChars',
    'IsNumericDomain', 'BrandInSubdomain', 'BrandDotCom',
    'ConsonantGroups', 'IsOnSuspiciousPlatform',

    # Structure
    'HasAt', 'HasPort', 'HasDoubleSlash', 'HasRedirectParam',
]

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club',
    'sbs', 'cfd', 'click', 'casa', 'vip', 'love', 'ink',
    'lk', 'cn', 'ru', 'bz'
}

SUSPICIOUS_PLATFORMS = {
    'pages.dev', 'vercel.app', 'replit.app', 'netlify.app',
    'github.io', 'blogspot.com', 'weebly.com', 'surge.sh',
    'workers.dev', 'framer.website', 'framer.app', 'glitch.me'
}

BRANDS = {
    'paypal', 'google', 'facebook', 'meta', 'apple', 'amazon',
    'microsoft', 'bank', 'roblox', 'ledger', 'trezor', 'binance',
    'netflix', 'instagram', 'steam', 'spotify'
}

SUSPICIOUS_WORDS = {'login', 'secure', 'verify', 'update', 'confirm', 'signin'}

TRUSTED_TLDS = {'edu.vn', 'gov.vn', 'edu', 'gov', 'ac.uk', 'ac.jp'}


def extract_features(url):
    try:
        parsed = urlparse(url.strip())
        domain = parsed.hostname or ''
        if not domain:
            return None
    except:
        return None

    normalized = url.strip()
    length = max(len(normalized), 1)
    path = parsed.path or ''
    query = parsed.query or ''

    # --- Lexical cơ bản ---
    url_length = len(normalized)
    domain_length = len(domain)

    is_ip = 1 if re.match(r'^(\d+\.){3}\d+$', domain) else 0

    tld = domain.split('.')[-1].lower() if '.' in domain else ''
    tld_length = len(tld)

    subdomains = domain.split('.')
    subdomain_count = max(len(subdomains) - 2, 0)

    letters = len(re.findall(r'[A-Za-z]', normalized))
    digits = len(re.findall(r'\d', normalized))
    equals = normalized.count('=')
    qmarks = normalized.count('?')
    ampersands = normalized.count('&')
    other_specials = len(re.findall(r'[!@#$%^&*()_+\[\]{}|;:,<>`~\"\']', normalized))
    spacial_ratio = (length - letters - digits) / length

    is_https = 1 if parsed.scheme.lower() == 'https' else 0

    # --- Entropy ---
    counts = {}
    for c in normalized.lower():
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum((v/length) * math.log2(v/length) for v in counts.values())

    # --- Obfuscation ---
    encoded_matches = re.findall(r'%[0-9a-fA-F]{2}', path)
    no_obfuscated = len(encoded_matches)
    has_obfuscation = 1 if no_obfuscated > 0 else 0
    obfuscation_ratio = no_obfuscated / length

    # --- Keyword ---
    keyword_text = f"{domain} {path} {query}".lower()
    bank = 1 if 'bank' in keyword_text else 0
    pay = 1 if 'pay' in keyword_text else 0
    crypto = 1 if re.search(r'crypto|bitcoin|wallet', keyword_text) else 0
    has_suspicious_word = 1 if any(w in domain.lower() for w in SUSPICIOUS_WORDS) else 0

    # --- Domain pattern ---
    has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    domain_dash_count = domain.count('-')
    has_repeated_chars = 1 if re.search(r'(.)\1{2,}', domain) else 0

    domain_main = subdomains[-2] if len(subdomains) >= 2 else ''
    is_numeric_domain = 1 if re.match(r'^\d+$', domain_main) else 0

    brand_in_subdomain = 0
    if subdomain_count > 0:
        first_sub = subdomains[0].lower()
        if any(b in first_sub for b in BRANDS):
            brand_in_subdomain = 1

    brand_dot_com = 1 if any(f"{b}.com." in domain.lower() for b in BRANDS) else 0

    consonant_groups = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', domain.lower()))

    is_on_suspicious_platform = 1 if any(domain.endswith(p) for p in SUSPICIOUS_PLATFORMS) else 0

    # --- Structure ---
    has_at = 1 if '@' in normalized else 0
    has_port = 1 if parsed.port else 0
    has_double_slash = 1 if '//' in path else 0
    has_redirect_param = 1 if re.search(r'(url=|redirect=|next=|goto=)', query, re.I) else 0

    return [
        url_length, domain_length, is_ip, tld_length,
        subdomain_count, letters, letters/length,
        digits, digits/length, equals,
        qmarks, ampersands, other_specials,
        spacial_ratio, is_https,

        entropy,

        has_obfuscation, no_obfuscated, obfuscation_ratio,

        bank, pay, crypto, has_suspicious_word,

        has_suspicious_tld, domain_dash_count, has_repeated_chars,
        is_numeric_domain, brand_in_subdomain, brand_dot_com,
        consonant_groups, is_on_suspicious_platform,

        has_at, has_port, has_double_slash, has_redirect_param,
    ]

# Load model
sess = rt.InferenceSession('model_phiusiil.onnx')

# Lấy 1 URL phishing từ dataset
url = "http://xn--53-6kch0fa.xn--p1ai/wp-content/themes/vass_theme/fonts/ttf/404mun/que.php"  # thay bằng URL thật từ CSV
features = extract_features(url)

X = np.array([features], dtype=np.float32)
pred = sess.run(None, {'float_input': X})
print("Label:", pred[0])
print("Probabilities:", pred[1])