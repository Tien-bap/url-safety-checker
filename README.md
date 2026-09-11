# URL Safety Checker — Version 1

Một công cụ kiểm tra URL chạy hoàn toàn ở phía client bằng JavaScript. Ứng dụng không có backend và không gửi URL người dùng nhập đến server. Bản demo được triển khai trên GitHub Pages:

[https://tien-bap.github.io/url-safety-checker](https://tien-bap.github.io/url-safety-checker)

> Đây là một mô hình phân tích tĩnh. Hệ thống chỉ đọc chuỗi URL và các đặc trưng có thể suy ra từ chuỗi đó; không truy cập website đích, không tải nội dung trang và không thực hiện dynamic analysis.

---

## Kiến trúc tổng thể

Luồng xử lý thực tế nằm trong `script.js` và gồm ba thành phần:

```text
URL người dùng nhập
                │
                ├── 1. SHA-256 + blacklist lookup
                │       └── Khớp hash → NGUY HIỂM tuyệt đối
                │
                ├── 2. Static analysis
                │       └── Sinh các flags để hiển thị giải thích
                │
                └── 3. Hai LightGBM model qua ONNX
                                ├── Domain model: 26 features
                                └── URL model: 40 features
                                                │
                                                └── riskScore = 70% URL + 30% domain
```

### Cách ra kết quả cuối cùng

1. Ứng dụng tính SHA-256 trên đúng chuỗi URL người dùng nhập và tra trong `hashes.json`. Nếu hash khớp blacklist, kết quả là `NGUY HIỂM` bất kể hai model đánh giá thế nào.
2. Nếu không khớp hash, ứng dụng chạy domain model và URL model.
3. Với mỗi model, `probPhishing` là xác suất lớp `Phishing` do ONNX trả về. Điểm tổng hợp được tính:

     ```text
     riskScore = 0.7 × probPhishing(URL)
                         + 0.3 × probPhishing(domain)
     ```

4. Nếu `riskScore >= 0.5`, kết quả là `NGUY HIỂM`; ngược lại là `AN TOÀN`.
5. `staticAnalysis()` không tham gia vào quyết định cuối. Các flags static chỉ được hiển thị để người dùng tham khảo và hiểu thêm các đặc điểm của URL.

Các bước inference chạy trong browser bằng `onnxruntime-web`. `script.js` hiện load:

- `models/model_lgbm_domain.onnx`
- `models/model_url_v2.onnx`

---

## Layer 1 — Hash-based Blacklist

### Nguồn dữ liệu

Blacklist được lưu trong `hashes.json`. Dữ liệu hash được tạo từ các URL độc hại thu thập từ những nguồn như:

- OpenPhish — phishing URLs.
- URLhaus của abuse.ch — malware URLs.

Các feed có thể thay đổi theo thời điểm cập nhật, vì vậy số lượng URL không cố định trong README này.

### Cơ chế lookup

```text
URL nhập vào
        → SHA-256
        → 8 ký tự đầu làm prefix
        → tìm bucket tương ứng trong hashes.json
        → so sánh full hash
```

Prefix chỉ giúp thu hẹp bucket; kết quả chỉ được xem là khớp khi full SHA-256 hash xuất hiện trong bucket đó. Ứng dụng không cần lưu URL gốc trong browser để thực hiện lookup.

Ví dụ cấu trúc `hashes.json`:

```json
{
    "a3f9bc12": [
        "a3f9bc12ef34...(full 64-character hash)"
    ],
    "ff00ee11": [
        "ff00ee112233..."
    ]
}
```

Blacklist chỉ nhận diện được URL đã có trong tập dữ liệu. Một URL phishing mới sẽ không khớp hash nếu chưa xuất hiện trong nguồn dữ liệu.

---

## Layer 2 — Static Analysis

Static analysis trong `extract-static.js` phân tích cấu trúc chuỗi URL bằng các rule đơn giản. Nó dùng cùng cách phân tách `suffix`, `registeredDomain` và `subdomainPrefix` với hai extractor ML ở mức thực dụng, bao gồm một bảng rút gọn cho các multi-label suffix như `com.vn` và `co.uk`.

Các nhóm tín hiệu gồm:

**Lexical và cấu trúc**

- Độ dài URL và path.
- Số lượng digit, dot, dash, underscore.
- Số lượng query parameter.
- Số lượng ký tự encoded trong path.
- Số lượng subdomain.

**Domain pattern**

- Domain là IP hoặc registered domain toàn số.
- Suspicious TLD như `.tk`, `.xyz`, `.top`, `.ru`, `.pw`, `.cc`, `.ws` và các TLD khác trong extractor.
- Brand xuất hiện trong subdomain hoặc registered domain.
- Từ khóa như `login`, `secure`, `verify`, `update`, `confirm`, `signin`, `account`, `password`.
- Ký tự lặp bất thường hoặc chuỗi consonant dài.
- Domain nằm trên các platform phổ biến như `pages.dev`, `vercel.app`, `github.io`, `blogspot.com`, `workers.dev`, `herokuapp.com`.

**URL structure**

- Không dùng HTTPS.
- Có ký tự `@`.
- Có port.
- Có `//` trong path.
- Có các redirect parameter như `url=`, `redirect=`, `next=`, `goto=`.

Static analysis không phải là một verdict độc lập. Một URL hợp lệ có thể có nhiều flags, và một URL độc hại có thể không có flag nào. Vì vậy các flags chỉ được hiển thị trong phần `Phân tích tĩnh` của giao diện.

---

## Layer 3 — Machine Learning

Hai model đều dùng LightGBM và được export sang ONNX để inference trong browser. Quy ước label của model:

```text
0 = Phishing
1 = Safe
```

Trong output ONNX, `probabilities[0]` được sử dụng làm `probPhishing` và `probabilities[1]` làm `probSafe`.

### 3.1 Domain model

Domain model chỉ nhìn hostname, không nhìn path và query. Domain được tách theo dạng:

```text
hostname → suffix + registeredDomain + subdomainPrefix
```

Extractor tương ứng là `extractDomainMLFeatures()` trong `extract-domain.js`, tạo **26 features**:

| Nhóm | Features |
|---|---|
| Cấu trúc | `DomainLength`, `SuffixLength`, `NoOfSubdomainLevels`, `RegisteredDomainLength`, `DashCount`, `UnderscoreCount` |
| Digit và lexical | `DigitRatioInRegisteredDomain`, `DigitCountInRegisteredDomain`, `EntropyRegisteredDomain`, `EntropySubdomainPrefix`, `VowelRatioRegisteredDomain`, `ConsonantGroupCount`, `LongestWordLength`, `TokenCount` |
| Brand | `BrandSubstringInSubdomain`, `BrandWordBoundaryInSubdomain`, `BrandSubstringInRegisteredDomain`, `BrandWordBoundaryInRegisteredDomain`, `MinBrandLevenshteinDistanceNormalized` |
| Suspicious pattern | `HasSuspiciousTLD`, `HasSuspiciousWord`, `HasFinancialWord`, `IsOnKnownPlatformSuffix`, `IsIP` |
| Encoding và domain đặc biệt | `HasPunycode`, `IsNumericRegisteredDomain` |

Với IP address, extractor sử dụng một vector đặc biệt thay vì cố gắng tách hostname bằng PSL.

### 3.2 URL model

URL model nhìn toàn bộ chuỗi URL, gồm protocol, hostname, path và query. Extractor tương ứng là `extractMLFeatures()` trong `extract-url.js`, tạo **40 features**:

| Nhóm | Features |
|---|---|
| Lexical | `URLLength`, `DomainLength`, `IsDomainIP`, `SuffixLength`, `NoOfSubDomain`, `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`, `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfOtherSpecialCharsInURL`, `SpacialCharRatioInURL`, `IsHTTPS` |
| Entropy | `Entropy`, `EntropyRegisteredDomain` |
| Obfuscation | `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio` |
| Keyword | `Bank`, `Pay`, `Crypto`, `HasSuspiciousWord` |
| Domain pattern | `HasSuspiciousTLD`, `DomainDashCount`, `HasRepeatedChars`, `IsNumericDomain`, `BrandSubstringInSubdomain`, `BrandWordBoundaryInSubdomain`, `BrandSubstringInRegisteredDomain`, `BrandWordBoundaryInRegisteredDomain`, `MinBrandLevenshteinDistanceNormalized`, `ConsonantGroups`, `IsOnSuspiciousPlatform` |
| Trust và structure | `IsTrustedSuffix`, `HasAt`, `HasPort`, `HasDoubleSlash`, `HasRedirectParam` |

Extractor của hai model đều chuẩn hóa hostname về lowercase và hỗ trợ input không có scheme bằng cách thêm `https://` trước khi parse.

---

## Nguồn dữ liệu và quá trình compile



Các bước chính:

1. Dữ liệu domain thô được làm sạch trong `clean_domain.py`: normalize lowercase, bỏ `www.`, loại domain rỗng/không hợp lệ, bỏ label conflict và duplicate.
2. `fetch.py` merge `raw_domains_final.csv` với dữ liệu benign từ `github_pages_benign.csv` và xử lý conflict label.
3. `clean_domain.py` có thể tạo thêm benign subdomain từ một tập domain hợp lệ bằng các prefix phổ biến như `login`, `secure`, `api`, `mail`, `support`.
4. `compile_dataset_domain.py` đọc `dataset/raw_domains_augmented.csv`, chạy `extract_domain_features()` và ghi:

     ```text
     dataset/dataset_domain_augmented.csv
     ```

Dataset cuối giữ lại cột `domain`, 26 feature columns và `label`.

### 2. URL dataset

`compile_dataset_full_url.py` tạo tập raw gồm ba cột `url`, `domain`, `label` từ các nguồn:

| Nguồn | Vai trò |
|---|---|
| `PhiUSIIL_Phishing_URL_Dataset.csv` | URL đã có label từ dataset phishing URL |
| OpenPhish feed | Phishing URL đang được ghi nhận |
| URLhaus feed | Malware URL |
| `phishing-links-ACTIVE.txt` | Phishing links đang hoạt động |
| `balanced_urls.csv` | Bổ sung URL benign/phishing đã cân bằng |
| `malicious_phish.csv` | Giữ các loại `benign`, `phishing`, `malware`; bỏ `defacement` |

Sau khi gom dữ liệu, script deduplicate theo `url` và ghi:

```text
dataset/raw_urls_with_domain.csv
```

Tiếp theo, `extract_full_url.py` dùng `tldextract` để tách domain theo Public Suffix List, tạo 40 features cho mỗi URL và ghi:

```text
dataset/dataset_url_with_domain.csv
```

Các dòng không parse được được lưu riêng trong `skipped_urls.csv` hoặc `skipped_domains.csv` để kiểm tra thay vì loại bỏ âm thầm.

---

## Huấn luyện và export model

### Quy trình chung

Hai script training dùng `lightgbm.LGBMClassifier` với các tham số chính:

```text
n_estimators = 500
learning_rate = 0.05
num_leaves = 127
random_state = 42
```

Class imbalance được xử lý bằng `scale_pos_weight` tính trên training set. Dữ liệu được chia bằng `GroupShuffleSplit`, không để cùng domain hoặc cùng apex domain xuất hiện đồng thời ở train và test. Đây là cách giảm leakage do nhiều URL có thể cùng thuộc một domain.

### Domain model

Script: `ML/train_domain_lgbm_model.py`

- Input: `dataset/dataset_domain_augmented.csv`.
- Group key: apex domain, tức registered domain kết hợp với suffix.
- Input size: 26 features.
- Output training artifact theo script: `ML/model_domain.onnx`.
- Artifact đang được frontend load: `models/model_lgbm_domain.onnx`.

Kết quả được ghi trong `models/model_lgbm_domain_report.txt`. Group split hiện tại cho thấy ROC AUC khoảng `0.8526`, accuracy khoảng `0.80`; đây là lý do không nên diễn giải output model như một sự xác nhận chắc chắn.

### URL model

Script: `ML/train_url_lgbm_model.py`

- Input: `dataset/dataset_url_with_domain.csv`.
- Group key: `domain`.
- Input size: 40 features.
- Output: `ML/model_url_v2.onnx`.
- Frontend load: `models/model_url_v2.onnx`.

Các file `model_lgbm_url_report.txt` và `model_lgbm_url.onnx` là artifact của phiên bản URL model trước đó. Cần kiểm tra đúng số feature trước khi thay model trong `script.js`; frontend hiện yêu cầu 40 features cho `model_url_v2.onnx`.

### False positive và false negative

Các script training xuất các mẫu dự đoán sai để review thủ công:

- `dataset/false_negatives_review.csv`
- `dataset/false_positives_review.csv`
- `dataset/url_false_negatives_review.csv`
- `dataset/url_false_positives_review.csv`

Các file này hữu ích để phát hiện dataset bias, kiểm tra label và quyết định có cần retrain hay điều chỉnh feature hay không.

---

## Cấu trúc file chính

| File | Vai trò |
|---|---|
| `index.html` | Giao diện và load các JavaScript module |
| `script.js` | Runtime pipeline, hash lookup, inference và tổng hợp kết quả |
| `extract-static.js` | Rule-based static analysis chỉ để giải thích |
| `extract-domain.js` | Extract 26 features cho domain model |
| `extract-url.js` | Extract 40 features cho URL model |
| `hashes.json` | Prefix bucket của full SHA-256 hashes |
| `models/model_lgbm_domain.onnx` | Domain model frontend đang sử dụng |
| `models/model_url_v2.onnx` | URL model frontend đang sử dụng |
| `ML/compile_dataset_domain.py` | Compile domain features |
| `ML/compile_dataset_full_url.py` | Gom raw URL từ nhiều nguồn |
| `ML/extract_full_url.py` | Extract 40 URL features |
| `ML/train_domain_lgbm_model.py` | Train/export domain model |
| `ML/train_url_lgbm_model.py` | Train/export URL model |

---

## Chạy local

Vì browser thường chặn `fetch()` khi mở trực tiếp bằng `file://`, nên nên chạy một static server tại thư mục gốc:

```bash
python3 -m http.server 8000
```

Sau đó mở:

```text
http://localhost:8000
```

Ứng dụng cần tải được `hashes.json` và hai file ONNX trong thư mục `models/`.

---

## Chú ý về độ tin cậy và giới hạn

Đây là phần rất quan trọng khi sử dụng kết quả của công cụ:

- Hệ thống chỉ phân tích **string của URL**: độ dài, ký tự, entropy, hostname, suffix, subdomain, path, query và một số keyword/pattern.
- Hệ thống **không mở URL**, không gửi HTTP request tới website đích, không kiểm tra response, HTML, JavaScript, redirect thực tế, cookie hay hành vi tải file.
- Hệ thống không kiểm tra domain age, DNS reputation, WHOIS, certificate chain, nội dung website, thông tin đăng nhập giả, malware runtime hoặc hành vi sau khi người dùng truy cập.
- `https://` không đồng nghĩa với an toàn. HTTPS chỉ nói rằng kết nối có mã hóa; domain phishing vẫn có thể dùng certificate hợp lệ.
- Một URL độc hại được tạo mới có thể chưa có trong blacklist và có thể không chứa pattern mà model đã học.
- Một URL hợp lệ có query dài, subdomain nhiều tầng, brand name hoặc keyword nhạy cảm có thể bị đánh giá rủi ro cao hơn thực tế.
- Dataset có thể chứa duplicate, label noise, bias theo nguồn dữ liệu và bias theo thời điểm thu thập. Group split giúp giảm leakage nhưng không loại bỏ các vấn đề này.
- Các probability từ LightGBM là output của model trên dữ liệu đã huấn luyện, không phải xác suất an toàn tuyệt đối đã được calibration theo mọi tình huống thực tế.
- Vì vậy kết quả hiện tại chỉ nên xem là **tín hiệu hỗ trợ sàng lọc**, không phải bằng chứng xác nhận URL an toàn hoặc độc hại.

Trong thực tế, URL bị đánh dấu `NGUY HIỂM` nên được xử lý thận trọng. URL được đánh dấu `AN TOÀN` vẫn cần được kiểm tra thêm bằng browser isolation, threat intelligence service hoặc các hệ thống dynamic/reputation analysis nếu mức độ rủi ro cao.

---

## Tech Stack

| Thành phần | Công nghệ |
|---|---|
| Frontend/hosting | HTML, JavaScript, GitHub Pages |
| Hashing | CryptoJS, SHA-256 |
| Browser inference | onnxruntime-web |
| Model training | LightGBM, scikit-learn, Python |
| Feature extraction | JavaScript và Python |
| Domain parsing | `tldextract` ở bước training; simplified PSL mapping ở browser |
| ONNX export | `onnxmltools`, `skl2onnx` |
| Dataset processing | pandas, requests, rapidfuzz tùy chọn |

---

## Hướng phát triển

Các hướng mở rộng nếu cần tăng độ tin cậy:

- Dùng Public Suffix List đầy đủ trong browser thay vì bảng suffix rút gọn.
- Calibration probability và đánh giá threshold theo cost của false positive/false negative.
- Cập nhật dataset thường xuyên hơn, kiểm tra label conflict và drift theo thời gian.
- Bổ sung reputation lookup, DNS, WHOIS, certificate và redirect chain.
- Thêm sandbox/dynamic analysis để kiểm tra nội dung và hành vi thực tế của URL.
- Tách rõ kết quả `unknown` khi hai model không đủ dữ liệu thay vì buộc về `Safe` hoặc `Phishing`.
