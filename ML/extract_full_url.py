import re
import math
import pandas as pd
from urllib.parse import urlparse
from multiprocessing import Pool, cpu_count
import tldextract

try:
    from rapidfuzz.distance import Levenshtein as _rf_lev
    def levenshtein(s1, s2):
        return _rf_lev.distance(s1, s2)
except ImportError:
    def levenshtein(s1, s2):
        if len(s1) < len(s2):
            return levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]


FEATURE_NAMES = [
    # Lexical cơ bản
    'URLLength', 'DomainLength', 'IsDomainIP', 'SuffixLength',
    'NoOfSubDomain', 'NoOfLettersInURL', 'LetterRatioInURL',
    'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL',
    'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL',
    'SpacialCharRatioInURL', 'IsHTTPS',

    # Entropy
    'Entropy',
    'EntropyRegisteredDomain',

    # Obfuscation
    'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio',

    # Keyword
    'Bank', 'Pay', 'Crypto', 'HasSuspiciousWord',

    # Domain pattern
    'HasSuspiciousTLD', 'DomainDashCount', 'HasRepeatedChars',
    'IsNumericDomain',
    'BrandSubstringInSubdomain', 'BrandWordBoundaryInSubdomain',
    'BrandSubstringInRegisteredDomain', 'BrandWordBoundaryInRegisteredDomain',
    'MinBrandLevenshteinDistanceNormalized',
    'ConsonantGroups', 'IsOnSuspiciousPlatform',

    # Trust signal — mới thêm để xử lý domain giáo dục/chính phủ
    'IsTrustedSuffix',

    # Structure
    'HasAt', 'HasPort', 'HasDoubleSlash', 'HasRedirectParam',
]

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club',
    'sbs', 'cfd', 'click', 'casa', 'vip', 'love', 'ink',
    'lk', 'cn', 'ru', 'bz', 'pw', 'cc', 'ws', 'nu'
}

SUSPICIOUS_PLATFORMS = {
    'pages.dev', 'vercel.app', 'replit.app', 'netlify.app',
    'github.io', 'blogspot.com', 'weebly.com', 'surge.sh',
    'workers.dev', 'framer.website', 'framer.app', 'glitch.me',
    'herokuapp.com', 'azurewebsites.net', '000webhostapp.com',
    'weeblysite.com', 'godaddysites.com', 'duckdns.org',
}

BRANDS = [
    'paypal', 'google', 'facebook', 'meta', 'apple', 'amazon',
    'microsoft', 'roblox', 'ledger', 'trezor', 'binance',
    'netflix', 'instagram', 'steam', 'spotify', 'twitter',
    'whatsapp', 'telegram', 'coinbase', 'kraken', 'chase',
    'wellsfargo', 'citibank', 'barclays', 'hsbc', 'alibaba',
]
_MAX_BRAND_LEN = max(len(b) for b in BRANDS)
_BRAND_PATTERNS = {
    b: re.compile(r'(?<![a-z0-9])' + re.escape(b) + r'(?![a-z0-9])')
    for b in BRANDS
}


def brand_word_match(text, brands=BRANDS):
    return any(_BRAND_PATTERNS[b].search(text) for b in brands)


SUSPICIOUS_WORDS = {'login', 'secure', 'verify', 'update', 'confirm', 'signin'}

# Suffix đáng tin cậy cao hơn mặt bằng chung — giáo dục, chính phủ, tổ chức học thuật.
# Đây là các suffix do PSL (tldextract) trả về đúng chuẩn (đã gồm ghép nhiều cấp).
TRUSTED_SUFFIXES = {
    'edu', 'edu.vn', 'edu.cn', 'edu.au', 'edu.my', 'edu.sg', 'edu.hk',
    'gov', 'gov.vn', 'gov.uk', 'gov.au', 'gov.cn', 'gov.sg',
    'ac.uk', 'ac.jp', 'ac.kr', 'ac.nz', 'ac.th',
    'go.jp', 'go.kr', 'go.th',
}


def shannon_entropy(s):
    if not s:
        return 0.0
    length = len(s)
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum((v / length) * math.log2(v / length) for v in counts.values())


def extract_features(url):
    try:
        raw = url.strip()
        parsed = urlparse(raw if raw.startswith('http') else 'https://' + raw)
        domain = (parsed.hostname or '').lower()
        if not domain:
            return None
    except Exception:
        return None

    normalized = raw
    length = max(len(normalized), 1)
    path = parsed.path or ''
    query = parsed.query or ''

    # ===== Phân rã domain đúng chuẩn PSL (thay cho split('.')[-1] cũ) =====
    is_ip = 1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain) else 0

    if is_ip:
        suffix = ''
        registered_domain = ''
        subdomain_prefix = ''
        suffix_length = 0
        subdomain_count = 0
    else:
        ext = tldextract.extract(domain)
        suffix = ext.suffix or ''
        registered_domain = ext.domain or ''
        subdomain_prefix = ext.subdomain or ''
        suffix_length = len(suffix)
        subdomain_count = (subdomain_prefix.count('.') + 1) if subdomain_prefix else 0

        if not registered_domain:
            return None

    # --- Lexical cơ bản ---
    url_length = len(normalized)
    domain_length = len(domain)

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
    entropy = -sum((v / length) * math.log2(v / length) for v in counts.values())

    entropy_registered_domain = shannon_entropy(registered_domain) if registered_domain else 0.0

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
    has_suspicious_word = 1 if any(w in domain for w in SUSPICIOUS_WORDS) else 0

    # --- Domain pattern (đã sửa dùng suffix/registered_domain/subdomain_prefix đúng PSL) ---
    has_suspicious_tld = 1 if suffix in SUSPICIOUS_TLDS else 0
    domain_dash_count = domain.count('-')
    has_repeated_chars = 1 if re.search(r'(.)\1{2,}', domain) else 0

    is_numeric_domain = 1 if registered_domain.isdigit() else 0

    # Brand matching — cả substring (bắt brand ghép dính) và word-boundary
    # (loại trừ từ ghép tự nhiên vô hại), nhất quán với domain-model.
    brand_substring_in_subdomain = 1 if any(b in subdomain_prefix for b in BRANDS) else 0
    brand_wordboundary_in_subdomain = 1 if brand_word_match(subdomain_prefix) else 0

    brand_substring_in_registered_domain = 0
    brand_wordboundary_in_registered_domain = 0
    if registered_domain and registered_domain not in BRANDS:
        if any(b in registered_domain for b in BRANDS):
            brand_substring_in_registered_domain = 1
        if brand_word_match(registered_domain):
            brand_wordboundary_in_registered_domain = 1

    if registered_domain:
        rd_length = max(len(registered_domain), 1)
        min_dist = min(levenshtein(registered_domain, b) for b in BRANDS)
        min_brand_dist_normalized = min_dist / rd_length
    else:
        min_brand_dist_normalized = 1.0

    consonant_groups = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', registered_domain))

    # IsOnSuspiciousPlatform: check đúng suffix PSL, không phải domain.endswith() thô
    # (tránh false match kiểu "notgithub.io" nếu suffix parser sai — giờ đã dùng suffix chuẩn)
    is_on_suspicious_platform = 1 if suffix in SUSPICIOUS_PLATFORMS else 0

    # --- Trust signal: domain giáo dục / chính phủ ---
    is_trusted_suffix = 1 if suffix in TRUSTED_SUFFIXES else 0

    # --- Structure ---
    has_at = 1 if '@' in normalized else 0
    try:
        has_port = 1 if parsed.port else 0
    except ValueError:
        has_port = 0
    has_double_slash = 1 if '//' in path else 0
    has_redirect_param = 1 if re.search(r'(url=|redirect=|next=|goto=)', query, re.I) else 0

    return [
        url_length, domain_length, is_ip, suffix_length,
        subdomain_count, letters, letters / length,
        digits, digits / length, equals,
        qmarks, ampersands, other_specials,
        spacial_ratio, is_https,

        entropy,
        entropy_registered_domain,

        has_obfuscation, no_obfuscated, obfuscation_ratio,

        bank, pay, crypto, has_suspicious_word,

        has_suspicious_tld, domain_dash_count, has_repeated_chars,
        is_numeric_domain,
        brand_substring_in_subdomain, brand_wordboundary_in_subdomain,
        brand_substring_in_registered_domain, brand_wordboundary_in_registered_domain,
        min_brand_dist_normalized,
        consonant_groups, is_on_suspicious_platform,

        is_trusted_suffix,

        has_at, has_port, has_double_slash, has_redirect_param,
    ]


def process_row(row):
    url, domain, label = row
    f = extract_features(url)
    if f:
        return [domain] + f + [label]
    return None


if __name__ == '__main__':
    BASE = './dataset/'

    df = pd.read_csv(f'{BASE}raw_urls_with_domain_v3.csv')
    print(f"Tổng: {len(df)}")

    # Cache PSL trước khi vào Pool, tránh mỗi worker tự fetch riêng
    tldextract.extract('warmup.example.com')

    rows_input = list(zip(df['url'], df['domain'], df['label']))

    with Pool(processes=cpu_count()) as pool:
        results = pool.map(process_row, rows_input)

    skipped_rows = [rows_input[i] for i, r in enumerate(results) if r is None]
    results = [r for r in results if r is not None]

    print(f"Thành công: {len(results)}, Thất bại: {len(skipped_rows)}")

    if skipped_rows:
        pd.DataFrame(skipped_rows, columns=['url', 'domain', 'label']) \
            .to_csv(f'{BASE}skipped_urls.csv', index=False)
        print(f"Đã lưu {len(skipped_rows)} dòng bị skip vào {BASE}skipped_urls.csv để kiểm tra.")

    new_df = pd.DataFrame(results, columns=['domain'] + FEATURE_NAMES + ['label'])
    new_df.to_csv(f'{BASE}dataset_url_with_domain.csv', index=False)
    print("Đã lưu dataset_url_with_domain.csv")
    print(new_df['label'].value_counts())