// ==================== EXTRACT STATIC ====================
const STATIC_SUSPICIOUS_TLDS = new Set([
    'tk','ml','ga','cf','gq','xyz','top','club',
    'sbs','cfd','click','casa','vip','love','ink',
    'lk','cn','ru','bz','pw','cc','ws','nu'
]);

const STATIC_TRUSTED_SUFFIXES = new Set([
    'edu','edu.vn','edu.cn','edu.au','edu.my','edu.sg','edu.hk',
    'gov','gov.vn','gov.uk','gov.au','gov.cn','gov.sg',
    'ac.uk','ac.jp','ac.kr','ac.nz','ac.th',
    'go.jp','go.kr','go.th'
]);

const STATIC_PLATFORM_SUFFIXES = new Set([
    'github.io','pages.dev','vercel.app','netlify.app',
    'replit.app','repl.co','web.app','firebaseapp.com',
    'blogspot.com','weebly.com','surge.sh','workers.dev',
    'framer.website','framer.app','glitch.me','herokuapp.com',
    'azurewebsites.net','000webhostapp.com','dynadot.com',
    'weeblysite.com','godaddysites.com','duckdns.org'
]);

const STATIC_BRANDS = [
    'paypal','google','facebook','meta','apple','amazon',
    'microsoft','roblox','ledger','trezor','binance',
    'netflix','instagram','steam','spotify','twitter',
    'whatsapp','telegram','coinbase','kraken','chase',
    'wellsfargo','citibank','barclays','hsbc','alibaba'
];

const STATIC_SUSPICIOUS_WORDS = [
    'login','secure','verify','update','confirm','signin',
    'account','password','recover','reset','auth','access'
];

const STATIC_MULTI_LABEL_SUFFIXES = new Set([
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
    'co.th','or.th','ac.th','go.th'
]);

function staticPslExtract(hostname) {
    const labels = hostname.split('.').filter(label => label.length > 0);
    if (labels.length <= 1) {
        return { suffix: '', registeredDomain: labels[0] || '', subdomainPrefix: '' };
    }

    const lastTwo = labels.slice(-2).join('.');
    const suffixLabelCount = STATIC_MULTI_LABEL_SUFFIXES.has(lastTwo) ? 2 : 1;
    if (labels.length <= suffixLabelCount) {
        return { suffix: labels.join('.'), registeredDomain: '', subdomainPrefix: '' };
    }

    const suffix = labels.slice(-suffixLabelCount).join('.');
    const registeredDomain = labels[labels.length - suffixLabelCount - 1];
    const subdomainPrefix = labels.slice(0, labels.length - suffixLabelCount - 1).join('.');
    return { suffix, registeredDomain, subdomainPrefix };
}

function staticBrandWordMatch(text) {
    return STATIC_BRANDS.some(brand => {
        const pattern = new RegExp(`(^|[^a-z0-9])${brand}([^a-z0-9]|$)`, 'i');
        return pattern.test(text);
    });
}

function extractFeatures(url) {
    let parsed;
    try {
        let raw = url.trim();
        if (!raw.includes('://')) raw = 'https://' + raw;
        parsed = new URL(raw);
    } catch { return null; }

    const fullURL = url.trim();
    const domain = (parsed.hostname || '').toLowerCase();
    const path = parsed.pathname || '';
    const query = parsed.search ? parsed.search.substring(1) : '';
    if (!domain) return null;

    const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain) ? 1 : 0;
    const { suffix, registeredDomain, subdomainPrefix } = staticPslExtract(domain);
    if (!isIP && !registeredDomain) return null;
    if (STATIC_TRUSTED_SUFFIXES.has(suffix)) return { trusted: true };

    const urlLength = fullURL.length;
    const domainLength = domain.length;
    const pathLength = path.length;
    const digitCount = (fullURL.match(/\d/g) || []).length;
    const digitRatio = digitCount / (fullURL.length || 1);
    const dotCount = (domain.match(/\./g) || []).length;
    const domainDashCount = (domain.match(/-/g) || []).length;
    const underscoreCount = (domain.match(/_/g) || []).length;
    const atCount = (fullURL.match(/@/g) || []).length;
    const queryParamCount = query ? query.split('&').length : 0;
    const encodedCharCount = (path.match(/%[0-9a-fA-F]{2}/g) || []).length;
    const subdomainCount = subdomainPrefix ? subdomainPrefix.split('.').length : 0;

    const hasSuspiciousTLD = STATIC_SUSPICIOUS_TLDS.has(suffix) ? 1 : 0;
    const brandsInSubdomain = STATIC_BRANDS.some(brand => subdomainPrefix.includes(brand));
    const brandInSubdomain = brandsInSubdomain ? 1 : 0;
    const brandDotCom = registeredDomain && !STATIC_BRANDS.includes(registeredDomain) &&
        STATIC_BRANDS.some(brand => registeredDomain.includes(brand)) ? 1 : 0;
    const hasSuspiciousWord = STATIC_SUSPICIOUS_WORDS.some(word => domain.includes(word)) ? 1 : 0;
    const isOnSuspiciousPlatform = STATIC_PLATFORM_SUFFIXES.has(suffix) ? 1 : 0;
    const hasRepeatedChars = /(.)\1{2,}/.test(domain) ? 1 : 0;
    const isNumericDomain = /^\d+$/.test(registeredDomain) ? 1 : 0;
    const consonantGroups = (registeredDomain.match(/[bcdfghjklmnpqrstvwxyz]{4,}/g) || []).length;

    const isHTTPS = parsed.protocol === 'https:' ? 1 : 0;
    const hasAt = atCount > 0 ? 1 : 0;
    const hasPort = parsed.port !== '' ? 1 : 0;
    const hasDoubleSlash = path.includes('//') ? 1 : 0;
    const hasRedirectParam = /(url=|redirect=|next=|goto=)/i.test(query) ? 1 : 0;

    return {
        urlLength, domainLength, pathLength,
        digitRatio, dotCount, domainDashCount, underscoreCount,
        queryParamCount, encodedCharCount, subdomainCount,
        hasSuspiciousTLD, isIP, brandInSubdomain, brandDotCom,
        brandWordInSubdomain: staticBrandWordMatch(subdomainPrefix) ? 1 : 0,
        hasSuspiciousWord, isOnSuspiciousPlatform,
        hasRepeatedChars, isNumericDomain, consonantGroups,
        isHTTPS, hasAt, hasPort, hasDoubleSlash, hasRedirectParam
    };
}

function staticAnalysis(features) {
    if (features.trusted) return [];
    const flags = [];

    if (features.urlLength > 100) flags.push("URL quá dài");
    if (features.domainDashCount >= 4) flags.push("Quá nhiều dấu gạch ngang trong domain");
    if (features.subdomainCount > 2) flags.push("Quá nhiều subdomain");
    if (features.encodedCharCount > 5) flags.push("Nhiều ký tự encoded trong path");
    if (features.isIP) flags.push("Dùng IP thay domain");
    if (features.hasSuspiciousTLD) flags.push("TLD đáng ngờ");
    if (features.brandInSubdomain) flags.push("Brand name trong subdomain");
    if (features.brandDotCom) flags.push("Giả mạo brand kiểu brand.com.xx");
    if (features.hasSuspiciousWord) flags.push("Chứa từ nhạy cảm trong domain");
    if (features.hasRepeatedChars) flags.push("Domain có ký tự lặp bất thường");
    if (features.isNumericDomain) flags.push("Domain toàn số");
    if (features.consonantGroups > 0) flags.push("Domain chứa chuỗi ký tự vô nghĩa");
    if (features.isOnSuspiciousPlatform && features.consonantGroups > 0)
        flags.push("Domain random trên platform miễn phí");
    if (features.isOnSuspiciousPlatform && features.domainDashCount >= 3)
        flags.push("Domain random trên platform miễn phí");
    if (!features.isHTTPS) flags.push("Không dùng HTTPS");
    if (features.hasAt) flags.push("Có ký tự @ trong URL");
    if (features.hasPort) flags.push("Dùng port bất thường");
    if (features.hasDoubleSlash) flags.push("Có // trong path");
    if (features.hasRedirectParam) flags.push("Có redirect parameter");

    return flags;
}

