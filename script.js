// ==================== INIT ====================
let hash_map = null;
let domainSession = null;
let urlSession = null;

window.onload = async function() {
    try {
        const [hashResult, dSession, uSession] = await Promise.all([
            fetch('hashes.json'),
            ort.InferenceSession.create('./models/model_lgbm_domain.onnx'),
            ort.InferenceSession.create('./models/model_lgbm_url.onnx')
            
        ]);
        hash_map = await hashResult.json();
        domainSession = dSession;
        urlSession = uSession;
        console.log("Loaded", Object.keys(hash_map).length, "prefixes + 2 ONNX models");
    } catch (err) {
        console.error('Load failed:', err);
    }
}

// ==================== MAIN ====================
function handleURLInput() {
    if (!hash_map || !urlSession || !domainSession) {
        showResult({ verdict: "ĐANG TẢI", reason: "Vui lòng thử lại sau giây lát" });
        return;
    }
    const url = document.getElementById('urlInput').value.trim();
    if (!url) {
        showResult({ verdict: "KHÔNG HỢP LỆ", reason: "Vui lòng nhập URL" });
        return;
    }
    checkURL(url);
}

async function checkURL(url) {
    let inBlacklist = false;

    // LỚP 1: Blacklist
    const hash_url = sha256(url);
    const prefix = hash_url.slice(0, 8);
    if (hash_map.hasOwnProperty(prefix)) {
        if (hash_map[prefix].includes(hash_url)) {
            inBlacklist = true;
        }
    }

    // LỚP 2: Phân tích tĩnh
    const features = extractFeatures(url);
    if (!features) {
        showResult({ verdict: "KHÔNG HỢP LỆ", reason: "URL không hợp lệ", url });
        return;
    }
    const flags = staticAnalysis(features);

    // LỚP 3: ML — Domain model + URL model
    const domainFeatures = extractDomainMLFeatures(url);
    const urlFeatures = extractMLFeatures(url);

    const domainResult = await predictWithSession(domainSession, domainFeatures, 26);
    const urlResult = await predictWithSession(urlSession, urlFeatures, 40);

    // Static analysis 
    const riskScore = calculateRiskScore(domainResult, urlResult);
    const isDangerousByModel = riskScore !== null && riskScore >= 0.5;

    if (inBlacklist) {
        showResult({
            verdict: "NGUY HIỂM",
            reason: "URL có trong blacklist",
            flags, domainResult, urlResult, riskScore, url, inBlacklist
        });
    } else if (isDangerousByModel) {
        showResult({
            verdict: "NGUY HIỂM",
            reason: "Điểm rủi ro từ mô hình vượt ngưỡng 50%",
            flags, domainResult, urlResult, riskScore, url, inBlacklist
        });
    } else {
        showResult({
            verdict: "AN TOÀN",
            reason: "Điểm rủi ro từ mô hình dưới ngưỡng 50%",
            flags, domainResult, urlResult, riskScore, url, inBlacklist
        });
    }
}

function calculateRiskScore(domainResult, urlResult) {
    if (!domainResult || !urlResult) return null;
    return (urlResult.probPhishing * 0.7) + (domainResult.probPhishing * 0.3);
}

// ==================== SHA256 ====================
function sha256(text) {
    return CryptoJS.SHA256(text).toString();
}

// ==================== ONNX ====================
async function predictWithSession(session, features, nFeatures) {
    if (!session || !features) return null;
    try {
        const input = new ort.Tensor('float32', Float32Array.from(features), [1, nFeatures]);
        const output = await session.run({ float_input: input });
        const label = Number(output.label.data[0]);
        const probs = output.probabilities.data;
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
function showResult({ verdict, reason, flags = [], domainResult, urlResult, riskScore, url, inBlacklist = false }) {
    const isSafe = verdict === 'AN TOÀN';
    const result = document.getElementById('result');
    const scoreText = riskScore === null ? 'Không đủ dữ liệu' : `${(riskScore * 100).toFixed(1)}%`;
    const scoreWidth = riskScore === null ? 0 : Math.min(riskScore * 100, 100);
    const flagsHTML = flags.length > 0
        ? flags.map(flag => `<li>${escapeHTML(flag)}</li>`).join('')
        : '<li>Không phát hiện dấu hiệu đặc biệt</li>';

    result.className = `result-card ${isSafe ? 'is-safe' : 'is-danger'}`;
    result.innerHTML = `
        <div class="result-header">
            <div>
                <span class="result-kicker">KẾT QUẢ ĐÁNH GIÁ</span>
                <h2>${escapeHTML(verdict)}</h2>
                <p class="result-reason">${escapeHTML(reason)}</p>
            </div>
            <div class="status-mark" aria-hidden="true">${isSafe ? '✓' : '!'}</div>
        </div>
        <div class="checked-url">${escapeHTML(url)}</div>
        <section class="risk-panel">
            <div class="risk-heading">
                <span>Điểm rủi ro tổng hợp</span>
                <strong>${scoreText}</strong>
            </div>
            <div class="risk-track"><span style="width:${scoreWidth}%"></span></div>
            <small>70% mô hình URL + 30% mô hình domain${inBlacklist ? ' · Hash blacklist: khớp tuyệt đối' : ''}</small>
        </section>
        <div class="model-grid">
            ${modelCard('Mô hình URL', urlResult)}
            ${modelCard('Mô hình domain', domainResult)}
        </div>
        <details class="static-details">
            <summary>Phân tích tĩnh (${flags.length} dấu hiệu)</summary>
            <ul>${flagsHTML}</ul>
        </details>
    `;
}

function modelCard(title, modelResult) {
    if (!modelResult) {
        return `<div class="model-card"><span>${title}</span><strong>Không có dữ liệu</strong></div>`;
    }
    return `
        <div class="model-card">
            <span>${title}</span>
            <strong>${modelResult.name}</strong>
            <small>Nguy hiểm ${(modelResult.probPhishing * 100).toFixed(1)}% · An toàn ${(modelResult.probSafe * 100).toFixed(1)}%</small>
        </div>
    `;
}

function escapeHTML(value) {
    return String(value).replace(/[&<>'"]/g, character => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
    }[character]));
}
