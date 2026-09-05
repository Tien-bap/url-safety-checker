// ==================== INIT ====================
let hash_map = null;
let mlSession = null;

window.onload = async function() {
    try {
        const [hashResult, session] = await Promise.all([
            fetch('hashes.json'),
            ort.InferenceSession.create('model_lgbm.onnx')
        ]);
        hash_map = await hashResult.json();
        mlSession = session;
        console.log("Loaded", Object.keys(hash_map).length, "prefixes");
    } catch (err) {
        console.error('Load failed:', err);
    }
}

// ==================== MAIN ====================
function handleURLInput() {
    if (!hash_map || !mlSession) {
        showResult("ĐANG TẢI", "Vui lòng thử lại sau giây lát", [], null);
        return;
    }
    const url = document.getElementById('urlInput').value.trim();
    if (!url) {
        showResult("KHÔNG HỢP LỆ", "Vui lòng nhập URL", [], null);
        return;
    }
    checkURL(url);
}

async function checkURL(url) {
    let inBlacklist = false;
    let flags = [];
    let mlResult = null;

    // LỚP 1: Blacklist
    const hash_url = sha256(url);
    const prefix = hash_url.slice(0, 8);
    if (hash_map.hasOwnProperty(prefix)) {
        const bucket = hash_map[prefix];
        if (bucket.includes(hash_url)) {
            inBlacklist = true;
        }
    }

    // LỚP 2: Phân tích tĩnh
    const features = extractFeatures(url);
    if (!features) {
        showResult("KHÔNG HỢP LỆ", "URL không hợp lệ", [], null);
        return;
    }
    flags = staticAnalysis(features);

    // LỚP 3: ML
    const mlFeatures = extractMLFeatures(url);
    if (mlFeatures) {
        mlResult = await predictWithONNX(mlFeatures);
    }

    // Tổng hợp kết quả
    const mlIsDangerous = mlResult && mlResult.label === 0;

    if (inBlacklist) {
        showResult("NGUY HIỂM", "Có trong blacklist", flags, mlResult);
    } else if (flags.length > 0 || mlIsDangerous) {
        showResult("NGUY HIỂM", "Phát hiện dấu hiệu nguy hiểm", flags, mlResult);
    } else {
        showResult("AN TOÀN", "Không phát hiện dấu hiệu nguy hiểm", [], mlResult);
    }
}

// ==================== SHA256 ====================
function sha256(text) {
    return CryptoJS.SHA256(text).toString();
}

// ==================== ONNX ====================
async function predictWithONNX(features) {
    if (!mlSession) return null;
    const input = new ort.Tensor('float32', Float32Array.from(features), [1, 35]);
    
    try {
        const output = await mlSession.run({ float_input: input });

        const label = Number(output.label.data[0]); // BigInt → Number
        const probs = output.probabilities.data;     // Float32Array

        return {
            label,
            name: label === 0 ? 'Phishing' : 'Safe',
            probPhishing: probs[0],
            probSafe: probs[1]
        };
    } catch(err) {
        console.error("ONNX error:", err);
        return null;
    }
}

// ==================== SHOW RESULT ====================
function showResult(verdict, reason, flags, mlResult) {
    const verdictColor = verdict === 'AN TOÀN' ? 'green' : verdict === 'ĐÁNG NGỜ' ? 'orange' : 'red';

    const flagsHTML = flags.length > 0
        ? `<p>Phân tích tĩnh: ${flags.join(', ')}</p>`
        : `<p>Phân tích tĩnh: Không phát hiện</p>`;

    const mlHTML = mlResult
        ? `<p>ML: ${mlResult.name} (Phishing: ${(mlResult.probPhishing * 100).toFixed(1)}% | Safe: ${(mlResult.probSafe * 100).toFixed(1)}%)</p>`
        : '';

    const blacklistHTML = reason === 'Có trong blacklist'
        ? `<p>Blacklist: Có trong danh sách đen</p>`
        : '';

    document.getElementById('result').innerHTML = `
        <strong style="color:${verdictColor}">${verdict}</strong>
        ${blacklistHTML}
        ${flagsHTML}
        ${mlHTML}
    `;
}

function staticAnalysis(features) {
    if (features.trusted) return [];
 
    const flags = [];
 
    // Lexical
    if (features.urlLength > 100) flags.push("URL quá dài");
    if (features.domainDashCount >= 4) flags.push("Quá nhiều dấu gạch ngang trong domain");
    if (features.subdomainCount > 2) flags.push("Quá nhiều subdomain");
    if (features.encodedCharCount > 5) flags.push("Nhiều ký tự encoded trong path");
 
    // Domain
    if (features.isIP) flags.push("Dùng IP thay domain");
    if (features.hasSuspiciousTLD) flags.push("TLD đáng ngờ");
    if (features.brandInSubdomain) flags.push("Brand name trong subdomain");
    if (features.brandDotCom) flags.push("Giả mạo brand kiểu brand.com.xx");
    if (features.hasSuspiciousWord) flags.push("Chứa từ nhạy cảm trong domain");
    if (features.hasRepeatedChars) flags.push("Domain có ký tự lặp bất thường");
    if (features.isNumericDomain) flags.push("Domain toàn số");
    if (features.consonantGroups > 0) flags.push("Domain chứa chuỗi ký tự vô nghĩa");
 
    // Platform + random domain
    if (features.isOnSuspiciousPlatform && features.consonantGroups > 0)
        flags.push("Domain random trên platform miễn phí");
    if (features.isOnSuspiciousPlatform && features.domainDashCount >= 3)
        flags.push("Domain random trên platform miễn phí");
 
    // Structure
    if (!features.isHTTPS) flags.push("Không dùng HTTPS");
    if (features.hasAt) flags.push("Có ký tự @ trong URL");
    if (features.hasPort) flags.push("Dùng port bất thường");
    if (features.hasDoubleSlash) flags.push("Có // trong path");
    if (features.hasRedirectParam) flags.push("Có redirect parameter");
 
    return flags;
}
 

function extractFeatures(url) {
    let parsed;
    try { parsed = new URL(url); }
    catch { return null; }
 
    const domain = parsed.hostname;
    const path = parsed.pathname;
    const query = parsed.search;
    const fullURL = url;
    const originAndPath = parsed.origin + parsed.pathname;
 
    // Whitelist TLD tin cậy
    const trustedTLDs = ['.edu.vn', '.gov.vn', '.edu', '.gov', '.ac.uk', '.ac.jp'];
    if (trustedTLDs.some(t => domain.endsWith(t))) return { trusted: true };
 
    // --- Lexical ---
    const urlLength = originAndPath.length;
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
 
    // --- Domain ---
    const subdomains = domain.split('.');
    const subdomainCount = subdomains.length - 2;
    const domainMainPart = subdomains[subdomains.length - 2] || '';
 
    const extendedSuspiciousTLDs = [
        '.tk', '.ml', '.ga', '.cf', '.gq',
        '.xyz', '.top', '.club', '.sbs', '.cfd',
        '.click', '.casa', '.vip', '.love', '.ink',
        '.lk', '.cn', '.ru', '.bz'
    ];
    const hasSuspiciousTLD = extendedSuspiciousTLDs.some(t => domain.endsWith(t)) ? 1 : 0;
    const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(domain) ? 1 : 0;
 
    const brands = ['paypal', 'google', 'facebook', 'meta', 'apple', 
                 'amazon', 'microsoft', 'bank', 'roblox', 'ledger', 
                 'trezor', 'binance', 'netflix', 'instagram', 'steam', 'spotify'];
    const brandInSubdomain = (subdomainCount > 0 && brands.some(b => subdomains[0].includes(b))) ? 1 : 0;
    const brandDotCom = brands.some(b => domain.includes(b + '.com.')) ? 1 : 0;
 
    const suspiciousWords = ['login', 'secure', 'verify', 'update', 'confirm', 'signin'];
    const hasSuspiciousWord = suspiciousWords.some(w => domain.toLowerCase().includes(w)) ? 1 : 0;
 
    // Platform miễn phí bị lạm dụng
    const suspiciousPlatforms = [
        'pages.dev', 'vercel.app', 'replit.app', 'netlify.app',
        'github.io', 'blogspot.com', 'weebly.com', 'surge.sh',
        'workers.dev', 'framer.website', 'framer.app', 'glitch.me'
    ];
    const isOnSuspiciousPlatform = suspiciousPlatforms.some(p => domain.endsWith(p)) ? 1 : 0;
 
    // Typosquatting — lặp ký tự (liivee, rriive)
    const hasRepeatedChars = /(.)\1{2,}/.test(domain) ? 1 : 0;
 
    // Domain toàn số
    const isNumericDomain = /^\d+$/.test(domainMainPart) ? 1 : 0;
 
    // Chuỗi consonant vô nghĩa
    const consonantGroups = (domain.match(/[bcdfghjklmnpqrstvwxyz]{4,}/gi) || []).length;
 
    // --- Structure ---
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
        hasSuspiciousWord, isOnSuspiciousPlatform,
        hasRepeatedChars, isNumericDomain, consonantGroups,
        isHTTPS, hasAt, hasPort, hasDoubleSlash, hasRedirectParam
    };
}

function extractMLFeatures(url) {
    let parsed;
    try { parsed = new URL(url.trim()); }
    catch { return null; }
 
    const domain = parsed.hostname || '';
    if (!domain) return null;
 
    const normalized = url.trim();
    const length = Math.max(normalized.length, 1);
    const path = parsed.pathname || '';
    const query = parsed.search ? parsed.search.substring(1) : ''; // bỏ dấu ?
 
    // --- Lexical ---
    const urlLength = normalized.length;
    const domainLength = domain.length;
    const isIP = /^(\d+\.){3}\d+$/.test(domain) ? 1 : 0;
    const tld = domain.includes('.') ? domain.split('.').pop().toLowerCase() : '';
    const tldLength = tld.length;
    const subdomains = domain.split('.');
    const subdomainCount = Math.max(subdomains.length - 2, 0);
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
    for (const c of normalized.toLowerCase()) {
        counts[c] = (counts[c] || 0) + 1;
    }
    const entropy = -Object.values(counts).reduce((sum, v) => {
        const p = v / length;
        return sum + p * Math.log2(p);
    }, 0);
 
    // --- Obfuscation (chỉ trong path) ---
    const encodedMatches = path.match(/%[0-9a-fA-F]{2}/g) || [];
    const noObfuscated = encodedMatches.length;
    const hasObfuscation = noObfuscated > 0 ? 1 : 0;
    const obfuscationRatio = noObfuscated / length;
 
    // --- Keyword ---
    const keywordText = `${domain} ${path} ${query}`.toLowerCase();
    const bank = keywordText.includes('bank') ? 1 : 0;
    const pay = keywordText.includes('pay') ? 1 : 0;
    const crypto = /crypto|bitcoin|wallet/.test(keywordText) ? 1 : 0;
    const suspiciousWords = ['login', 'secure', 'verify', 'update', 'confirm', 'signin'];
    const hasSuspiciousWord = suspiciousWords.some(w => domain.toLowerCase().includes(w)) ? 1 : 0;
 
    // --- Domain pattern ---
    const suspiciousTLDs = new Set([
        'tk','ml','ga','cf','gq','xyz','top','club',
        'sbs','cfd','click','casa','vip','love','ink','lk','cn','ru','bz'
    ]);
    const hasSuspiciousTLD = suspiciousTLDs.has(tld) ? 1 : 0;
    const domainDashCount = (domain.match(/-/g) || []).length;
    const hasRepeatedChars = /(.)\1{2,}/.test(domain) ? 1 : 0;
    const domainMain = subdomains.length >= 2 ? subdomains[subdomains.length - 2] : '';
    const isNumericDomain = /^\d+$/.test(domainMain) ? 1 : 0;
 
    const brands = ['paypal','google','facebook','meta','apple','amazon',
                    'microsoft','bank','roblox','ledger','trezor','binance',
                    'netflix','instagram','steam','spotify'];
    const brandInSubdomain = (subdomainCount > 0 && brands.some(b => subdomains[0].toLowerCase().includes(b))) ? 1 : 0;
    const brandDotCom = brands.some(b => domain.toLowerCase().includes(b + '.com.')) ? 1 : 0;
    const consonantGroups = (domain.toLowerCase().match(/[bcdfghjklmnpqrstvwxyz]{4,}/g) || []).length;
 
    const suspiciousPlatforms = [
        'pages.dev','vercel.app','replit.app','netlify.app',
        'github.io','blogspot.com','weebly.com','surge.sh',
        'workers.dev','framer.website','framer.app','glitch.me'
    ];
    const isOnSuspiciousPlatform = suspiciousPlatforms.some(p => domain.endsWith(p)) ? 1 : 0;
 
    // --- Structure ---
    const hasAt = normalized.includes('@') ? 1 : 0;
    const hasPort = parsed.port !== '' ? 1 : 0;
    const hasDoubleSlash = path.includes('//') ? 1 : 0;
    const hasRedirectParam = /(url=|redirect=|next=|goto=)/i.test(query) ? 1 : 0;
 
    // Trả về array đúng thứ tự FEATURE_NAMES
    return [
        urlLength, domainLength, isIP, tldLength,
        subdomainCount, letters, letters/length,
        digits, digits/length, equals,
        qmarks, ampersands, otherSpecials,
        spacialRatio, isHTTPS,
 
        entropy,
 
        hasObfuscation, noObfuscated, obfuscationRatio,
 
        bank, pay, crypto, hasSuspiciousWord,
 
        hasSuspiciousTLD, domainDashCount, hasRepeatedChars,
        isNumericDomain, brandInSubdomain, brandDotCom,
        consonantGroups, isOnSuspiciousPlatform,
 
        hasAt, hasPort, hasDoubleSlash, hasRedirectParam,
    ];
}