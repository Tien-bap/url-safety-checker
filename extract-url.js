// ==================== EXTRACT ML URL (40 features) ====================

const URL_SUSPICIOUS_TLDS = new Set([
    'tk','ml','ga','cf','gq','xyz','top','club',
    'sbs','cfd','click','casa','vip','love','ink',
    'lk','cn','ru','bz','pw','cc','ws','nu'
]);

const URL_SUSPICIOUS_PLATFORMS = new Set([
    'pages.dev','vercel.app','replit.app','netlify.app',
    'github.io','blogspot.com','weebly.com','surge.sh',
    'workers.dev','framer.website','framer.app','glitch.me',
    'herokuapp.com','azurewebsites.net','000webhostapp.com',
    'weeblysite.com','godaddysites.com','duckdns.org',
]);

const URL_BRANDS = [
    'paypal','google','facebook','meta','apple','amazon',
    'microsoft','roblox','ledger','trezor','binance',
    'netflix','instagram','steam','spotify','twitter',
    'whatsapp','telegram','coinbase','kraken','chase',
    'wellsfargo','citibank','barclays','hsbc','alibaba',
];

const URL_TRUSTED_SUFFIXES = new Set([
    'edu','edu.vn','edu.cn','edu.au','edu.my','edu.sg','edu.hk',
    'gov','gov.vn','gov.uk','gov.au','gov.cn','gov.sg',
    'ac.uk','ac.jp','ac.kr','ac.nz','ac.th',
    'go.jp','go.kr','go.th',
]);

const URL_SUSPICIOUS_WORDS = new Set(['login','secure','verify','update','confirm','signin']);

// Bảng suffix nhiều-nhãn phổ biến (bản rút gọn của PSL, đủ dùng thực tế cho các case phổ biến)
const URL_MULTI_LABEL_SUFFIXES = new Set([
    'co.uk','org.uk','gov.uk','ac.uk','me.uk','net.uk','sch.uk',
    'com.au','net.au','org.au','edu.au','gov.au',
    'co.jp','ne.jp','or.jp','ac.jp','go.jp',
    'com.br','net.br','org.br','gov.br',
    'com.cn','net.cn','org.cn','gov.cn','edu.cn',
    'com.vn','net.vn','org.vn','edu.vn','gov.vn','ac.vn','biz.vn',
    'co.in','net.in','org.in','gov.in','ac.in',
    'co.kr','or.kr','ne.kr','go.kr','ac.kr',
    'com.tw','net.tw','org.tw','gov.tw',
    'com.hk','net.hk','org.hk','gov.hk','edu.hk',
    'co.id','net.id','or.id','go.id',
    'com.my','net.my','org.my','gov.my','edu.my',
    'com.sg','net.sg','org.sg','gov.sg','edu.sg',
    'com.mx','net.mx','org.mx','gob.mx',
    'com.ar','net.ar','org.ar','gob.ar',
    'co.nz','net.nz','org.nz','govt.nz','ac.nz',
    'co.za','net.za','org.za','gov.za',
    'co.th','or.th','ac.th','go.th',
]);

function urlShannonEntropy(s) {
    if (!s) return 0.0;
    const length = s.length;
    const counts = {};
    for (const c of s) counts[c] = (counts[c] || 0) + 1;
    return -Object.values(counts).reduce((sum, v) => {
        const p = v / length;
        return sum + p * Math.log2(p);
    }, 0);
}

function urlLevenshtein(s1, s2) {
    if (s1.length < s2.length) return urlLevenshtein(s2, s1);
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

function urlBrandWordMatch(text) {
    for (const b of URL_BRANDS) {
        const re = new RegExp(`(^|[^a-z0-9])${b}([^a-z0-9]|$)`, 'i');
        if (re.test(text)) return true;
    }
    return false;
}

// Simplified tldextract equivalent — trả về { suffix, registeredDomain, subdomainPrefix }
function urlPslExtract(hostname) {
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

function extractMLFeatures(url) {
    let parsed;
    try {
        let raw = url.trim();
        if (!raw.startsWith('http')) raw = 'https://' + raw;
        parsed = new URL(raw);
    } catch {
        return null;
    }

    const domain = (parsed.hostname || '').toLowerCase();
    if (!domain) return null;

    const normalized = url.trim();
    const length = Math.max(normalized.length, 1);
    const path = parsed.pathname || '';
    const query = parsed.search ? parsed.search.substring(1) : '';

    // ===== Phân rã domain theo PSL (khớp tldextract) =====
    const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain) ? 1 : 0;

    let suffix = '', registeredDomain = '', subdomainPrefix = '';
    let suffixLength = 0, subdomainCount = 0;

    if (isIP) {
        // giữ nguyên rỗng, giống Python
    } else {
        const ext = urlPslExtract(domain);
        suffix = ext.suffix;
        registeredDomain = ext.registeredDomain;
        subdomainPrefix = ext.subdomainPrefix;
        suffixLength = suffix.length;
        subdomainCount = subdomainPrefix ? (subdomainPrefix.split('.').length) : 0;

        if (!registeredDomain) return null;
    }

    // --- Lexical cơ bản ---
    const urlLength = normalized.length;
    const domainLength = domain.length;

    const letters = (normalized.match(/[A-Za-z]/g) || []).length;
    const digits = (normalized.match(/\d/g) || []).length;
    const equals = (normalized.match(/=/g) || []).length;
    const qmarks = (normalized.match(/\?/g) || []).length;
    const ampersands = (normalized.match(/&/g) || []).length;
    const otherSpecials = (normalized.match(/[!@#$%^&*()_+\[\]{}|;:,<>`~\"\']/g) || []).length;
    const spacialRatio = (length - letters - digits) / length;

    const isHTTPS = parsed.protocol === 'https:' ? 1 : 0;

    // --- Entropy ---
    const counts = {};
    for (const c of normalized.toLowerCase()) counts[c] = (counts[c] || 0) + 1;
    const entropy = -Object.values(counts).reduce((sum, v) => {
        const p = v / length;
        return sum + p * Math.log2(p);
    }, 0);

    const entropyRegisteredDomain = registeredDomain ? urlShannonEntropy(registeredDomain) : 0.0;

    // --- Obfuscation ---
    const encodedMatches = path.match(/%[0-9a-fA-F]{2}/g) || [];
    const noObfuscated = encodedMatches.length;
    const hasObfuscation = noObfuscated > 0 ? 1 : 0;
    const obfuscationRatio = noObfuscated / length;

    // --- Keyword ---
    const keywordText = `${domain} ${path} ${query}`.toLowerCase();
    const bank = keywordText.includes('bank') ? 1 : 0;
    const pay = keywordText.includes('pay') ? 1 : 0;
    const crypto = /crypto|bitcoin|wallet/.test(keywordText) ? 1 : 0;
    const hasSuspiciousWord = [...URL_SUSPICIOUS_WORDS].some(w => domain.includes(w)) ? 1 : 0;

    // --- Domain pattern ---
    const hasSuspiciousTLD = URL_SUSPICIOUS_TLDS.has(suffix) ? 1 : 0;
    const domainDashCount = (domain.match(/-/g) || []).length;
    const hasRepeatedChars = /(.)\1{2,}/.test(domain) ? 1 : 0; // giữ nguyên như Python: KHÔNG strip www
    const isNumericDomain = /^\d+$/.test(registeredDomain) ? 1 : 0;

    const brandSubstringInSubdomain = URL_BRANDS.some(b => subdomainPrefix.includes(b)) ? 1 : 0;
    const brandWordboundaryInSubdomain = urlBrandWordMatch(subdomainPrefix) ? 1 : 0;

    let brandSubstringInRegisteredDomain = 0;
    let brandWordboundaryInRegisteredDomain = 0;
    if (registeredDomain && !URL_BRANDS.includes(registeredDomain)) {
        if (URL_BRANDS.some(b => registeredDomain.includes(b))) brandSubstringInRegisteredDomain = 1;
        if (urlBrandWordMatch(registeredDomain)) brandWordboundaryInRegisteredDomain = 1;
    }

    let minBrandDistNormalized;
    if (registeredDomain) {
        const rdLength = Math.max(registeredDomain.length, 1);
        const minDist = Math.min(...URL_BRANDS.map(b => urlLevenshtein(registeredDomain, b)));
        minBrandDistNormalized = minDist / rdLength;
    } else {
        minBrandDistNormalized = 1.0;
    }

    const consonantGroups = (registeredDomain.match(/[bcdfghjklmnpqrstvwxyz]{4,}/g) || []).length;

    const isOnSuspiciousPlatform = URL_SUSPICIOUS_PLATFORMS.has(suffix) ? 1 : 0;

    // --- Trust signal ---
    const isTrustedSuffix = URL_TRUSTED_SUFFIXES.has(suffix) ? 1 : 0;

    // --- Structure ---
    const hasAt = normalized.includes('@') ? 1 : 0;
    const hasPort = parsed.port !== '' ? 1 : 0;
    const hasDoubleSlash = path.includes('//') ? 1 : 0;
    const hasRedirectParam = /(url=|redirect=|next=|goto=)/i.test(query) ? 1 : 0;

    return [
        urlLength, domainLength, isIP, suffixLength,
        subdomainCount, letters, letters / length,
        digits, digits / length, equals,
        qmarks, ampersands, otherSpecials,
        spacialRatio, isHTTPS,

        entropy,
        entropyRegisteredDomain,

        hasObfuscation, noObfuscated, obfuscationRatio,

        bank, pay, crypto, hasSuspiciousWord,

        hasSuspiciousTLD, domainDashCount, hasRepeatedChars,
        isNumericDomain,
        brandSubstringInSubdomain, brandWordboundaryInSubdomain,
        brandSubstringInRegisteredDomain, brandWordboundaryInRegisteredDomain,
        minBrandDistNormalized,
        consonantGroups, isOnSuspiciousPlatform,

        isTrustedSuffix,

        hasAt, hasPort, hasDoubleSlash, hasRedirectParam,
    ];
}