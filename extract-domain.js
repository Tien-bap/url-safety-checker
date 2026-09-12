
// ==================== EXTRACT ML DOMAIN (26 features) ====================

const DOMAIN_FEATURE_NAMES = [
    'DomainLength', 'SuffixLength', 'NoOfSubdomainLevels',
    'RegisteredDomainLength', 'DashCount', 'UnderscoreCount',
    'DigitRatioInRegisteredDomain', 'DigitCountInRegisteredDomain',

    'EntropyRegisteredDomain', 'EntropySubdomainPrefix',
    'VowelRatioRegisteredDomain', 'ConsonantGroupCount',
    'LongestWordLength', 'TokenCount',

    'BrandSubstringInSubdomain', 'BrandWordBoundaryInSubdomain',
    'BrandSubstringInRegisteredDomain', 'BrandWordBoundaryInRegisteredDomain',
    'MinBrandLevenshteinDistanceNormalized',
    'HasSuspiciousTLD', 'HasSuspiciousWord', 'HasFinancialWord',

    'IsOnKnownPlatformSuffix', 'IsIP',

    'HasPunycode', 'IsNumericRegisteredDomain',
];

const SUSPICIOUS_TLDS = new Set([
    'tk','ml','ga','cf','gq','xyz','top','club',
    'sbs','cfd','click','casa','vip','love','ink',
    'lk','cn','ru','bz','pw','cc','ws','nu'
]);

const KNOWN_PLATFORM_SUFFIXES = new Set([
    'github.io','pages.dev','vercel.app','netlify.app',
    'replit.app','repl.co','web.app','firebaseapp.com',
    'blogspot.com','weebly.com','surge.sh','workers.dev',
    'framer.website','framer.app','glitch.me','herokuapp.com',
    'azurewebsites.net','000webhostapp.com','dynadot.com',
    'weeblysite.com','godaddysites.com','duckdns.org',
]);

// Bảng suffix nhiều-nhãn phổ biến (KHÔNG đầy đủ như PSL thật — chỉ đủ dùng thực tế).
// Nếu cần chính xác tuyệt đối như Python (tldextract dùng full Public Suffix List),
// cần bundle file public_suffix_list.dat và parse — nặng hơn nhiều cho web app.
const MULTI_LABEL_SUFFIXES = new Set([
    'co.uk','org.uk','gov.uk','ac.uk','me.uk','net.uk','sch.uk',
    'com.au','net.au','org.au','edu.au','gov.au',
    'co.jp','ne.jp','or.jp','ac.jp','go.jp',
    'com.br','net.br','org.br','gov.br',
    'com.cn','net.cn','org.cn','gov.cn',
    'com.vn','net.vn','org.vn','edu.vn','gov.vn','ac.vn','biz.vn',
    'co.in','net.in','org.in','gov.in','ac.in',
    'co.kr','or.kr','ne.kr','go.kr',
    'com.tw','net.tw','org.tw','gov.tw',
    'com.hk','net.hk','org.hk','gov.hk',
    'co.id','net.id','or.id','go.id',
    'com.my','net.my','org.my','gov.my',
    'com.sg','net.sg','org.sg','gov.sg',
    'com.mx','net.mx','org.mx','gob.mx',
    'com.ar','net.ar','org.ar','gob.ar',
    'co.nz','net.nz','org.nz','govt.nz',
    'co.za','net.za','org.za','gov.za',
]);

const BRANDS = [
    'paypal','google','facebook','meta','apple','amazon',
    'microsoft','roblox','ledger','trezor','binance',
    'netflix','instagram','steam','spotify','twitter',
    'whatsapp','telegram','coinbase','kraken','chase',
    'wellsfargo','citibank','barclays','hsbc','alibaba',
];
const MAX_BRAND_LEN = Math.max(...BRANDS.map(b => b.length));

const SUSPICIOUS_WORDS = new Set([
    'login','secure','verify','update','confirm','signin',
    'account','password','recover','reset','auth','access'
]);
const FINANCIAL_WORDS = new Set([
    'bank','pay','crypto','bitcoin','wallet','finance',
    'invest','trading','money','cash','transfer'
]);

// ---- Levenshtein ----
function levenshtein(s1, s2) {
    if (s1.length < s2.length) return levenshtein(s2, s1);
    if (s2.length === 0) return s1.length;
    let prev = Array.from({length: s2.length + 1}, (_, i) => i);
    for (const c1 of s1) {
        const curr = [prev[0] + 1];
        for (let j = 0; j < s2.length; j++) {
            curr.push(Math.min(prev[j+1]+1, curr[j]+1, prev[j]+(c1 !== s2[j] ? 1 : 0)));
        }
        prev = curr;
    }
    return prev[prev.length - 1];
}

// ---- Shannon entropy ----
function shannonEntropy(s) {
    if (!s) return 0.0;
    const length = s.length;
    const counts = {};
    for (const c of s) counts[c] = (counts[c] || 0) + 1;
    return -Object.values(counts).reduce((sum, v) => {
        const p = v / length;
        return sum + p * Math.log2(p);
    }, 0);
}

// ---- Brand word-boundary match: tương đương regex (?<![a-z0-9])brand(?![a-z0-9]) ----
function brandWordMatch(text) {
    for (const b of BRANDS) {
        const re = new RegExp(`(^|[^a-z0-9])${b}([^a-z0-9]|$)`, 'i');
        if (re.test(text)) return true;
    }
    return false;
}

// ---- Simplified tldextract equivalent ----
// Trả về { suffix, registeredDomain, subdomainPrefix }
function pslExtract(hostname) {
    const labels = hostname.split('.').filter(l => l.length > 0);
    if (labels.length === 0) return { suffix: '', registeredDomain: '', subdomainPrefix: '' };
    if (labels.length === 1) return { suffix: '', registeredDomain: labels[0], subdomainPrefix: '' };

    const lastTwo = labels.slice(-2).join('.');

    // Gộp cả suffix quốc gia (co.uk...) VÀ platform suffix (github.io, vercel.app...)
    // vì cả 2 loại đều là suffix 2 nhãn thật trong PSL
    let suffixLabelCount;
    if (MULTI_LABEL_SUFFIXES.has(lastTwo) || KNOWN_PLATFORM_SUFFIXES.has(lastTwo)) {
        suffixLabelCount = 2;
    } else {
        suffixLabelCount = 1;
    }

    if (labels.length <= suffixLabelCount) {
        return { suffix: labels.join('.'), registeredDomain: '', subdomainPrefix: '' };
    }

    const suffix = labels.slice(-suffixLabelCount).join('.');
    const registeredDomain = labels[labels.length - suffixLabelCount - 1];
    const subdomainLabels = labels.slice(0, labels.length - suffixLabelCount - 1);
    const subdomainPrefix = subdomainLabels.join('.');

    return { suffix, registeredDomain, subdomainPrefix };
}

// ---- IP feature vector (short-circuit, giống Python) ----
function ipFeatureVector(hostname) {
    return [
        hostname.length, 0, 0,
        0, (hostname.match(/-/g)||[]).length, (hostname.match(/_/g)||[]).length,
        0.0, 0,

        NaN, NaN,
        0.0, 0,
        0, 0,

        0, 0, 0, 0,
        1.0,
        0, 0, 0,

        0, 1,
        0, 1,
    ];
}

// ==================== MAIN EXTRACT FUNCTION ====================
function extractDomainMLFeatures(hostnameOrUrl) {
    let hostname;
    try {
        let raw = hostnameOrUrl.trim();
        if (!raw.includes('://')) raw = 'https://' + raw;
        hostname = (new URL(raw)).hostname;
    } catch {
        return null;
    }
    if (!hostname) return null;
    hostname = hostname.toLowerCase();

    // --- IP check (short-circuit) ---
    const isIPRaw = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (isIPRaw) {
        return ipFeatureVector(hostname);
    }

    const { suffix, registeredDomain, subdomainPrefix } = pslExtract(hostname);
    if (!registeredDomain) return null;

    // ===== Nhóm 1 — Cấu trúc cơ bản =====
    const domainLength = hostname.length;
    const suffixLength = suffix.length;
    const noOfSubdomainLevels = subdomainPrefix ? (subdomainPrefix.split('.').length) : 0;
    const registeredDomainLength = registeredDomain.length;
    const dashCount = (hostname.match(/-/g) || []).length;
    const underscoreCount = (hostname.match(/_/g) || []).length;

    const rdLength = Math.max(registeredDomainLength, 1);
    const digitCountRd = (registeredDomain.match(/\d/g) || []).length;
    const digitRatioRd = digitCountRd / rdLength;

    // ===== Nhóm 2 — Lexical / Entropy =====
    const entropyRd = shannonEntropy(registeredDomain);
    const entropySub = subdomainPrefix ? shannonEntropy(subdomainPrefix) : NaN;

    const lettersRd = registeredDomain.split('').filter(c => /[a-z]/i.test(c));
    const vowelCountRd = lettersRd.filter(c => 'aeiou'.includes(c.toLowerCase())).length;
    const vowelRatioRd = lettersRd.length > 0 ? vowelCountRd / lettersRd.length : 0.0;

    const consonantGroupCount = (registeredDomain.match(/[bcdfghjklmnpqrstvwxyz]{4,}/g) || []).length;

    const combinedForTokens = subdomainPrefix ? `${subdomainPrefix}.${registeredDomain}` : registeredDomain;
    const tokens = combinedForTokens.split(/[-.]/).filter(t => t.length > 0);
    const longestWordLength = tokens.length > 0 ? Math.max(...tokens.map(t => t.length)) : 0;
    const tokenCount = tokens.length;

    // ===== Nhóm 4 — Brand & suspicious pattern =====
    const brandSubstringInSubdomain = BRANDS.some(b => subdomainPrefix.includes(b)) ? 1 : 0;

    let brandSubstringInRegisteredDomain = 0;
    if (!BRANDS.includes(registeredDomain)) {
        if (BRANDS.some(b => registeredDomain.includes(b))) brandSubstringInRegisteredDomain = 1;
    }

    const brandWordboundaryInSubdomain = brandWordMatch(subdomainPrefix) ? 1 : 0;

    let brandWordboundaryInRegisteredDomain = 0;
    if (!BRANDS.includes(registeredDomain)) {
        if (brandWordMatch(registeredDomain)) brandWordboundaryInRegisteredDomain = 1;
    }

    const minDist = registeredDomain
        ? Math.min(...BRANDS.map(b => levenshtein(registeredDomain, b)))
        : MAX_BRAND_LEN;
    const minBrandDistNormalized = minDist / rdLength;

    const hasSuspiciousTLD = SUSPICIOUS_TLDS.has(suffix) ? 1 : 0;
    const hasSuspiciousWord = [...SUSPICIOUS_WORDS].some(w => hostname.includes(w)) ? 1 : 0;
    const hasFinancialWord = [...FINANCIAL_WORDS].some(w => hostname.includes(w)) ? 1 : 0;

    // ===== Nhóm 5 — Platform / hosting đặc biệt =====
    const isOnKnownPlatformSuffix = (
        KNOWN_PLATFORM_SUFFIXES.has(suffix) ||
        [...KNOWN_PLATFORM_SUFFIXES].some(p => hostname.endsWith('.' + p) || hostname === p)
    ) ? 1 : 0;

    // ===== Nhóm 6 — Encoding đặc biệt =====
    const hasPunycode = hostname.includes('xn--') ? 1 : 0;
    const isNumericRegisteredDomain = /^\d+$/.test(registeredDomain) ? 1 : 0;

    return [
        domainLength, suffixLength, noOfSubdomainLevels,
        registeredDomainLength, dashCount, underscoreCount,
        digitRatioRd, digitCountRd,

        entropyRd, entropySub,
        vowelRatioRd, consonantGroupCount,
        longestWordLength, tokenCount,

        brandSubstringInSubdomain, brandWordboundaryInSubdomain,
        brandSubstringInRegisteredDomain, brandWordboundaryInRegisteredDomain,
        minBrandDistNormalized,
        hasSuspiciousTLD, hasSuspiciousWord, hasFinancialWord,

        isOnKnownPlatformSuffix, isIPRaw ? 1 : 0,

        hasPunycode, isNumericRegisteredDomain,
    ];
}