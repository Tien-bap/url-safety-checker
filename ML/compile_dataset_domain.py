import time
import re
import math
import numpy as np
import pandas as pd
import tldextract

try:
    from rapidfuzz.distance import Levenshtein as _rf_lev
    def levenshtein(s1, s2):
        return _rf_lev.distance(s1, s2)
    print("[info] Dùng rapidfuzz cho Levenshtein (nhanh).")
except ImportError:
    print("[warn] Chưa cài rapidfuzz (pip install rapidfuzz --break-system-packages). "
          "Đang dùng bản Python thuần, sẽ CHẬM HƠN đáng kể trên dataset lớn.")
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


DOMAIN_FEATURE_NAMES = [
    # Nhóm 1 — Cấu trúc cơ bản
    'DomainLength', 'SuffixLength', 'NoOfSubdomainLevels',
    'RegisteredDomainLength', 'DashCount', 'UnderscoreCount',
    'DigitRatioInRegisteredDomain', 'DigitCountInRegisteredDomain',

    # Nhóm 2 — Lexical / Entropy
    'EntropyRegisteredDomain', 'EntropySubdomainPrefix',
    'VowelRatioRegisteredDomain', 'ConsonantGroupCount',
    'LongestWordLength', 'TokenCount',

    # Nhóm 4 — Brand & suspicious pattern
    'BrandSubstringInSubdomain', 'BrandWordBoundaryInSubdomain',
    'BrandSubstringInRegisteredDomain', 'BrandWordBoundaryInRegisteredDomain',
    'MinBrandLevenshteinDistanceNormalized',
    'HasSuspiciousTLD', 'HasSuspiciousWord', 'HasFinancialWord',

    # Nhóm 5 — Platform / hosting đặc biệt
    'IsOnKnownPlatformSuffix', 'IsIP',

    # Nhóm 6 — Encoding đặc biệt
    'HasPunycode', 'IsNumericRegisteredDomain',
]

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club',
    'sbs', 'cfd', 'click', 'casa', 'vip', 'love', 'ink',
    'lk', 'cn', 'ru', 'bz', 'pw', 'cc', 'ws', 'nu'
}

KNOWN_PLATFORM_SUFFIXES = {
    'github.io', 'pages.dev', 'vercel.app', 'netlify.app',
    'replit.app', 'repl.co', 'web.app', 'firebaseapp.com',
    'blogspot.com', 'weebly.com', 'surge.sh', 'workers.dev',
    'framer.website', 'framer.app', 'glitch.me', 'herokuapp.com',
    'azurewebsites.net', '000webhostapp.com', 'dynadot.com',
    'weeblysite.com', 'godaddysites.com', 'duckdns.org',
}

BRANDS = [
    'paypal', 'google', 'facebook', 'meta', 'apple', 'amazon',
    'microsoft', 'roblox', 'ledger', 'trezor', 'binance',
    'netflix', 'instagram', 'steam', 'spotify', 'twitter',
    'whatsapp', 'telegram', 'coinbase', 'kraken', 'chase',
    'wellsfargo', 'citibank', 'barclays', 'hsbc', 'alibaba',
]

SUSPICIOUS_WORDS = {
    'login', 'secure', 'verify', 'update', 'confirm', 'signin',
    'account', 'password', 'recover', 'reset', 'auth', 'access'
}
FINANCIAL_WORDS = {
    'bank', 'pay', 'crypto', 'bitcoin', 'wallet', 'finance',
    'invest', 'trading', 'money', 'cash', 'transfer'
}

_MAX_BRAND_LEN = max(len(b) for b in BRANDS)

_BRAND_PATTERNS = {
    b: re.compile(r'(?<![a-z0-9])' + re.escape(b) + r'(?![a-z0-9])')
    for b in BRANDS
}

def brand_word_match(text, brands=BRANDS):
    """Khớp brand như 1 'từ' độc lập (ngăn bởi ranh giới không phải chữ/số),
    tránh việc substring vô tình khớp trong từ ghép không liên quan
    (vd 'meta' trong 'metadata', 'chase' trong 'purchase')."""
    return any(_BRAND_PATTERNS[b].search(text) for b in brands)


def shannon_entropy(s):
    if not s:
        return 0.0
    length = len(s)
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum((v / length) * math.log2(v / length) for v in counts.values())


def _ip_feature_vector(hostname):
    """Feature vector riêng cho hostname là IP thuần — không đi qua PSL/lexical."""
    return [
        len(hostname), 0, 0,                              # DomainLength, SuffixLength, NoOfSubdomainLevels
        0, hostname.count('-'), hostname.count('_'),      # RegisteredDomainLength, DashCount, UnderscoreCount
        0.0, 0,                                           # DigitRatioInRegisteredDomain, DigitCountInRegisteredDomain

        np.nan, np.nan,                                   # EntropyRegisteredDomain, EntropySubdomainPrefix
        0.0, 0,                                           # VowelRatioRegisteredDomain, ConsonantGroupCount
        0, 0,                                             # LongestWordLength, TokenCount

        0, 0, 0, 0,                                       # BrandSubstringInSubdomain, BrandWordBoundaryInSubdomain, BrandSubstringInRegisteredDomain, BrandWordBoundaryInRegisteredDomain
        1.0,                                               # MinBrandLevenshteinDistanceNormalized (không match brand nào)
        0, 0, 0,                                          # HasSuspiciousTLD, HasSuspiciousWord, HasFinancialWord

        0, 1,                                             # IsOnKnownPlatformSuffix, IsIP
        0, 1,                                             # HasPunycode, IsNumericRegisteredDomain
    ]


def extract_domain_features(hostname):
    if not hostname or not isinstance(hostname, str):
        return None

    hostname = hostname.strip().lower()
    if not hostname:
        return None

    # --- IP check trước khi extract: short-circuit, không đi qua PSL/lexical ---
    is_ip = 1 if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname) else 0
    if is_ip:
        return _ip_feature_vector(hostname)

    ext = tldextract.extract(hostname)
    suffix = ext.suffix or ''
    registered_domain = ext.domain or ''
    subdomain_prefix = ext.subdomain or ''

    if not registered_domain:
        return None

    # ===== Nhóm 1 — Cấu trúc cơ bản =====
    domain_length = len(hostname)
    suffix_length = len(suffix)
    no_of_subdomain_levels = (subdomain_prefix.count('.') + 1) if subdomain_prefix else 0
    registered_domain_length = len(registered_domain)
    dash_count = hostname.count('-')
    underscore_count = hostname.count('_')

    rd_length = max(registered_domain_length, 1)
    digit_count_rd = sum(1 for c in registered_domain if c.isdigit())
    digit_ratio_rd = digit_count_rd / rd_length

    # ===== Nhóm 2 — Lexical / Entropy =====
    entropy_rd = shannon_entropy(registered_domain)
    entropy_sub = shannon_entropy(subdomain_prefix) if subdomain_prefix else np.nan

    letters_rd = [c for c in registered_domain if c.isalpha()]
    vowel_count_rd = sum(1 for c in letters_rd if c in 'aeiou')
    vowel_ratio_rd = (vowel_count_rd / len(letters_rd)) if letters_rd else 0.0

    consonant_group_count = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', registered_domain))

    combined_for_tokens = f"{subdomain_prefix}.{registered_domain}" if subdomain_prefix else registered_domain
    tokens = [t for t in re.split(r'[-.]', combined_for_tokens) if t]
    longest_word_length = max((len(t) for t in tokens), default=0)
    token_count = len(tokens)

    # ===== Nhóm 4 — Brand & suspicious pattern =====
        # --- Substring match (bắt cả brand ghép dính không dấu phân cách, vd 'paypalsecurelogin') ---
    brand_substring_in_subdomain = 1 if any(b in subdomain_prefix for b in BRANDS) else 0

    brand_substring_in_registered_domain = 0
    if registered_domain not in BRANDS:
        if any(b in registered_domain for b in BRANDS):
            brand_substring_in_registered_domain = 1

    # --- Word-boundary match (loại trừ từ ghép tự nhiên vô hại, vd 'metadata') ---
    brand_wordboundary_in_subdomain = 1 if brand_word_match(subdomain_prefix) else 0

    brand_wordboundary_in_registered_domain = 0
    if registered_domain not in BRANDS:
        if brand_word_match(registered_domain):
            brand_wordboundary_in_registered_domain = 1
    if registered_domain:
        min_dist = min(levenshtein(registered_domain, b) for b in BRANDS)
    else:
        min_dist = _MAX_BRAND_LEN
    min_brand_dist_normalized = min_dist / rd_length

    has_suspicious_tld = 1 if suffix in SUSPICIOUS_TLDS else 0
    has_suspicious_word = 1 if any(w in hostname for w in SUSPICIOUS_WORDS) else 0
    has_financial_word = 1 if any(w in hostname for w in FINANCIAL_WORDS) else 0

    # ===== Nhóm 5 — Platform / hosting đặc biệt =====
    is_on_known_platform_suffix = 1 if suffix in KNOWN_PLATFORM_SUFFIXES or any(
        hostname.endswith('.' + p) or hostname == p for p in KNOWN_PLATFORM_SUFFIXES
    ) else 0

    # ===== Nhóm 6 — Encoding đặc biệt =====
    has_punycode = 1 if 'xn--' in hostname else 0
    is_numeric_registered_domain = 1 if registered_domain.isdigit() else 0

    return [
        domain_length, suffix_length, no_of_subdomain_levels,
        registered_domain_length, dash_count, underscore_count,
        digit_ratio_rd, digit_count_rd,

        entropy_rd, entropy_sub,
        vowel_ratio_rd, consonant_group_count,
        longest_word_length, token_count,

        brand_substring_in_subdomain, brand_wordboundary_in_subdomain,
        brand_substring_in_registered_domain, brand_wordboundary_in_registered_domain,
        min_brand_dist_normalized,
        has_suspicious_tld, has_suspicious_word, has_financial_word,

        is_on_known_platform_suffix, is_ip,

        has_punycode, is_numeric_registered_domain,
    ]


BASE = './dataset/'
INPUT_FILE = f'{BASE}raw_domains_augmented.csv'
OUTPUT_FILE = f'{BASE}dataset_domain_augmented.csv'
SKIPPED_FILE = f'{BASE}skipped_domains.csv'


def main():
    df = pd.read_csv(INPUT_FILE)
    print(f"Đọc {len(df)} dòng từ {INPUT_FILE}")

    # Cache PSL 1 lần trước khi vào vòng lặp chính (tránh network access rải rác giữa chừng)
    tldextract.extract('warmup.example.com')

    rows = []
    skipped = []
    t0 = time.time()

    # itertuples nhanh hơn iterrows đáng kể vì không tạo Series cho mỗi dòng
    for i, r in enumerate(df.itertuples(index=False)):
        f = extract_domain_features(r.domain)
        if f is not None:
            rows.append([r.domain] + f + [r.label])
        else:
            skipped.append((r.domain, r.label))

        if (i + 1) % 200_000 == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed
            eta = (len(df) - (i + 1)) / rate
            print(f"  Đã xử lý {i + 1:,}/{len(df):,} "
                  f"({rate:.0f} dòng/s, ETA ~{eta / 60:.1f} phút)")

    elapsed = time.time() - t0
    print(f"\nHoàn tất extract trong {elapsed:.1f}s ({len(df) / elapsed:.0f} dòng/s)")

    df_final = pd.DataFrame(rows, columns=['domain'] + DOMAIN_FEATURE_NAMES + ['label'])

    print(f"\n=== TỔNG KẾT ===")
    print(f"Tổng dòng thành công: {len(df_final)}")
    print(f"Tổng dòng bị skip (extract trả None): {len(skipped)}")
    print(df_final['label'].value_counts())

    neg = len(df_final[df_final['label'] == 0])
    pos = len(df_final[df_final['label'] == 1])
    print(f"scale_pos_weight: {neg / pos:.4f}")

    # Lưu riêng các dòng bị skip để kiểm tra nguyên nhân, không để mất âm thầm
    if skipped:
        df_skipped = pd.DataFrame(skipped, columns=['domain', 'label'])
        df_skipped.to_csv(SKIPPED_FILE, index=False)
        print(f"\nĐã lưu {len(skipped)} dòng bị skip vào {SKIPPED_FILE} — nên xem qua để xác nhận "
              f"đây là rác thực sự, không phải domain hợp lệ bị lọc nhầm.")
        print("Mẫu 20 dòng bị skip:")
        print(df_skipped.head(20).to_string(index=False))

    df_final.to_csv(OUTPUT_FILE, index=False)
    print(f"\nĐã lưu {OUTPUT_FILE}")


if __name__ == '__main__':
    main()