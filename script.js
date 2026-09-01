function sha256(text) {
    return CryptoJS.SHA256(text).toString(); 
}

hash_map = null

onload = async function() {
    const result = await fetch('hashes.json');
    const data = await result.json();
    hash_map = data;
    console.log("Loaded", Object.keys(hash_map).length, "hashes");
}

function handleURLInput() {
     if (!hash_map) {
        showResult("⏳ Đang tải dữ liệu...", "Vui lòng thử lại sau giây lát", []);
        return;
    }
    const url = document.getElementById('urlInput').value;
    checkURL(url);
}


function checkURL(url) {
    const hash_url = sha256(url);
    const hash_url_8 = hash_url.slice(0, 8);
    
    if(hash_map.hasOwnProperty(hash_url_8)) {
        const fullHashes = hash_map[hash_url_8];
        if(fullHashes.includes(hash_url)) {
            showResult("NGUY HIỂM", "Có trong blacklist", []);
            return;
        }
    } 

    const features = extractFeatures(url);
    console.log(features.dashCount);
    if(!features) {
        showResult("KHÔNG HỢP LỆ", "URL không hợp lệ", []);
        return;
    }

    const flags = staticAnalysis(features);
    if(flags.length > 0) {
        showResult("NGUY HIỂM", "Phát hiện các dấu hiệu đáng ngờ", flags);
    } else {
        showResult("AN TOÀN", "Không phát hiện dấu hiệu đáng ngờ", []);
    }

}



function extractFeatures(url) {
    let parsed;
    try { parsed = new URL(url); }
    catch { return null; } // URL không hợp lệ

    const domain = parsed.hostname;
    const path = parsed.pathname;
    const query = parsed.search;
    const fullURL = url;

    // --- Lexical ---
    const urlLength = fullURL.length;
    const domainLength = domain.length;
    const pathLength = path.length;
    const digitCount = (fullURL.match(/\d/g) || []).length;
    const letterCount = (fullURL.match(/[a-zA-Z]/g) || []).length;
    const digitRatio = digitCount / (fullURL.length || 1);
    const dotCount = (fullURL.match(/\./g) || []).length;
    const dashCount = (fullURL.match(/-/g) || []).length;
    const underscoreCount = (fullURL.match(/_/g) || []).length;
    const atCount = (fullURL.match(/@/g) || []).length;
    const queryParamCount = query ? query.split('&').length : 0;
    const encodedCharCount = (fullURL.match(/%[0-9a-fA-F]{2}/g) || []).length;

    // --- Domain ---
    const subdomains = domain.split('.');
    const subdomainCount = subdomains.length - 2; // bỏ domain + TLD
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club'];
    const hasSuspiciousTLD = suspiciousTLDs.some(t => domain.endsWith(t)) ? 1 : 0;
    const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(domain) ? 1 : 0;
    const brands = ['paypal', 'google', 'facebook', 'apple', 'amazon', 'microsoft', 'bank'];
    const brandInSubdomain = (subdomainCount > 0 && brands.some(b => subdomains[0].includes(b))) ? 1 : 0;
    const suspiciousWords = ['login', 'secure', 'verify', 'account', 'update', 'confirm', 'signin'];
    const hasSuspiciousWord = suspiciousWords.some(w => fullURL.toLowerCase().includes(w)) ? 1 : 0;

    // --- Structure ---
    const isHTTPS = parsed.protocol === 'https:' ? 1 : 0;
    const hasAt = atCount > 0 ? 1 : 0;
    const hasPort = parsed.port !== '' ? 1 : 0;
    const hasDoubleSlash = path.includes('//') ? 1 : 0;
    const hasRedirectParam = /(url=|redirect=|next=|goto=)/i.test(query) ? 1 : 0;

    return {
        urlLength, domainLength, pathLength,
        digitRatio, dotCount, dashCount, underscoreCount,
        queryParamCount, encodedCharCount, subdomainCount,
        hasSuspiciousTLD, isIP, brandInSubdomain, hasSuspiciousWord,
        isHTTPS, hasAt, hasPort, hasDoubleSlash, hasRedirectParam
    };
}


function staticAnalysis(features) {
    const flags = [];

    if (features.urlLength > 100) flags.push("URL quá dài");
    if (features.isIP) flags.push("Dùng IP thay domain");
    if (features.hasSuspiciousTLD) flags.push("TLD đáng ngờ");
    if (features.brandInSubdomain) flags.push("Brand name trong subdomain");
    if (features.hasSuspiciousWord) flags.push("Chứa từ nhạy cảm");
    if (features.hasAt) flags.push("Có ký tự @ trong URL");
    if (features.hasDoubleSlash) flags.push("Có // trong path");
    if (features.hasRedirectParam) flags.push("Có redirect parameter");
    if (features.dashCount > 4) flags.push("Quá nhiều dấu gạch ngang");
    if (features.subdomainCount > 2) flags.push("Quá nhiều subdomain");
    if (!features.isHTTPS) flags.push("Không dùng HTTPS");
    if (features.encodedCharCount > 5) flags.push("Nhiều ký tự encoded");

    return flags;
}


function showResult(result, reason, flags){
    const flagList = flags.map(f => `<li>${f}</li>`).join('');
    document.getElementById('result').innerHTML = `
        <strong>${result}</strong>
        <p>${reason}</p>
        ${flags.length > 0 ? `<ul>${flagList}</ul>` : ''}
    `;
}
