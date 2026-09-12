# URL Safety Checker — Version 1

Công cụ kiểm tra URL chạy hoàn toàn phía client bằng JavaScript, không backend, không gửi URL người dùng lên server. Demo trên GitHub Pages:

[https://tien-bap.github.io/url-safety-checker](https://tien-bap.github.io/url-safety-checker)

> Đây là phân tích tĩnh: hệ thống chỉ đọc chuỗi URL và các đặc trưng suy ra được từ chuỗi đó, không truy cập website đích, không tải nội dung trang, không dynamic analysis.

---

## Kiến trúc tổng thể

```text
URL người dùng nhập
        │
        ├── 1. SHA-256 + blacklist lookup → khớp hash → NGUY HIỂM tuyệt đối
        │
        ├── 2. Static analysis → sinh flags để giải thích (không quyết định kết quả)
        │
        └── 3. Hai LightGBM model qua ONNX (chạy trong browser bằng onnxruntime-web)
                ├── Domain model — 26 features, chỉ nhìn hostname
                └── URL model    — 40 features, nhìn toàn bộ URL (path, query...)
                        │
                        └── riskScore = 0.7 × probPhishing(URL) + 0.3 × probPhishing(domain)
                            riskScore ≥ 0.5 → NGUY HIỂM, ngược lại → AN TOÀN
```

Cả hai model dùng chung quy ước label `0 = Phishing, 1 = Safe`.

---

## Layer 1 — Blacklist theo hash

Blacklist (`hashes.json`) chứa SHA-256 hash của URL độc hại thu thập từ OpenPhish và URLhaus. Lookup theo 2 bước: lấy 8 ký tự đầu của hash làm prefix để tìm bucket, sau đó so khớp full hash trong bucket đó — không cần lưu URL gốc trong browser.

Hạn chế cố hữu: chỉ nhận diện URL đã có trong dữ liệu, không bắt được URL phishing hoàn toàn mới.

---

## Layer 2 — Static analysis

Rule-based, chỉ dùng để hiển thị giải thích cho người dùng, **không tham gia quyết định cuối cùng**. Dùng chung cách tách `suffix / registeredDomain / subdomainPrefix` với hai extractor ML. Các nhóm tín hiệu: độ dài & cấu trúc URL, TLD đáng ngờ, brand trong subdomain, từ khóa nhạy cảm (login, verify, secure...), domain trên các platform dùng chung (vercel.app, github.io...), HTTPS/port/redirect bất thường.

---

## Layer 3 — Machine Learning (2 model)

### Domain model (26 features)

Chỉ nhìn hostname, tách theo `suffix + registeredDomain + subdomainPrefix`. Nhóm feature chính: cấu trúc (độ dài, số subdomain, dash/underscore), entropy & lexical (Shannon entropy, vowel ratio, consonant group, token dài nhất), brand matching (substring + word-boundary + Levenshtein distance chuẩn hóa tới brand gần nhất), suspicious pattern (TLD, keyword, platform, IP, punycode).

### URL model (40 features)

Nhìn toàn bộ chuỗi URL (protocol, hostname, path, query). Kế thừa các nhóm feature domain-level ở trên, cộng thêm: lexical toàn URL (độ dài, tỷ lệ chữ/số/ký tự đặc biệt), entropy toàn URL, obfuscation (ký tự encoded trong path), keyword tài chính (bank/pay/crypto), và structure (`@`, port, `//`, redirect param).

---

## Huấn luyện

Cả hai model dùng `LightGBM` (`n_estimators=500, learning_rate=0.05, num_leaves=127`), imbalance xử lý bằng `scale_pos_weight`. Điểm quan trọng nhất trong huấn luyện: **chia train/test bằng `GroupShuffleSplit` theo domain/apex domain**, không cho phép cùng một domain xuất hiện ở cả train và test — nếu không, model "học thuộc" domain thay vì học pattern, khiến accuracy bị ảo cao hơn thực tế.

Kết quả group-split (thực chất hơn random-split):

| Model | Accuracy | ROC AUC |
|---|---|---|
| Domain model | ~0.80 | ~0.85 |
| URL model | ~0.92 | ~0.97 |

Domain model thấp hơn URL model vì chỉ nhìn hostname, không có context path/query.

---

## Nguồn dữ liệu

**Domain dataset**: PhiUSIIL, OpenPhish, URLhaus, Phishing.Database, và benign domain (Tranco/GitHub Pages) được augment thêm subdomain phổ biến (`login`, `secure`, `api`, `mail`...).

**URL dataset**: PhiUSIIL, OpenPhish, URLhaus, Phishing.Database, `balanced_urls.csv`, `malicious_phish.csv` (bỏ nhãn `defacement`).

Domain được tách theo Public Suffix List thật (`tldextract`) ở bước training; ở browser dùng bảng suffix rút gọn tương đương (bao gồm cả TLD ghép như `co.uk`, `com.vn` và các platform suffix như `github.io`, `vercel.app`).

---

## Hai vấn đề dữ liệu quan trọng đã phát hiện và fix

**1. Noise nhãn ở domain giáo dục/chính phủ.** Nhiều domain uy tín (`*.edu`, `*.gov`, `*.ac.uk`...) bị gán nhầm label phishing trong dữ liệu gốc, vì một URL con nào đó từng bị compromise không có nghĩa domain apex nguy hiểm. Đã downsample lại tỷ lệ phishing trong nhóm domain edu/gov để phản ánh đúng thực tế, thay vì xóa sạch (vẫn giữ lại các case phishing thật trên domain bị compromise).

**2. Domain decomposition sai với platform suffix.** Bảng suffix rút gọn ở browser ban đầu không coi các platform dùng chung (`github.io`, `vercel.app`...) là suffix 2 nhãn giống PSL thật, dẫn đến parse sai — ví dụ `tien-bap.github.io` bị tách nhầm `registeredDomain="github"`, `subdomain="tien-bap"` thay vì `registeredDomain="tien-bap"`. Hệ quả: mọi URL trên các platform này bị model đánh giá sai vì nhận input khác hẳn lúc training. Đã fix bằng cách gộp danh sách platform suffix vào nhóm suffix 2 nhãn khi parse ở cả Python (training) và JavaScript (inference), đảm bảo hai bên nhất quán tuyệt đối.

---

## Giới hạn

- Chỉ phân tích chuỗi URL — không mở URL, không kiểm tra response/HTML/redirect thực tế, không WHOIS/DNS/certificate/domain age.
- HTTPS không đồng nghĩa an toàn.
- URL phishing hoàn toàn mới có thể không khớp blacklist và không trùng pattern model đã học.
- URL hợp lệ với query dài, nhiều subdomain, hoặc chứa brand/keyword nhạy cảm (SSO, session token...) có thể bị đánh giá rủi ro cao hơn thực tế.
- Dataset tổng hợp từ nhiều nguồn công khai nên khó tránh khỏi duplicate và label noise còn sót lại ngoài hai vấn đề đã fix ở trên.
- Kết quả chỉ nên xem là tín hiệu hỗ trợ sàng lọc, không phải xác nhận tuyệt đối.

---

## Tech Stack

| Thành phần | Công nghệ |
|---|---|
| Frontend/hosting | HTML, JavaScript, GitHub Pages |
| Hashing | CryptoJS (SHA-256) |
| Browser inference | onnxruntime-web |
| Model training | LightGBM, scikit-learn |
| Domain parsing | `tldextract` (training) / simplified PSL mapping (browser) |
| ONNX export | `onnxmltools`, `skl2onnx` |

---

## Hướng phát triển

- Dùng Public Suffix List đầy đủ trong browser thay vì bảng rút gọn.
- Calibration probability theo cost thật của false positive/negative.
- Bổ sung reputation lookup, WHOIS, certificate, redirect chain (Version 2 — cần backend).
- Tách riêng kết quả "unknown" khi model không đủ tin cậy, thay vì ép về Safe/Phishing.