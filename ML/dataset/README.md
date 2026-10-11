# Dataset chính thức (final)

Bộ dataset chính thức gồm bốn file bên dưới. Giữ nguyên tên và vị trí để các script hiện tại tiếp tục hoạt động. Các dataset nguồn, bản trung gian và file review khác đã được xóa khỏi thư mục này.

Quy ước nhãn: `0 = Phishing`, `1 = Safe`.

| Model | Dạng | File | Số dòng | Phishing (0) | Safe (1) | Dung lượng (MB) |
|---|---|---|---:|---:|---:|---:|
| domain | raw | [raw_domains_augmented.csv](raw_domains_augmented.csv) | 1,839,507 | 599,897 | 1,239,610 | 41.8 |
| domain | features | [dataset_domain_augmented.csv](dataset_domain_augmented.csv) | 1,836,501 | 596,962 | 1,239,539 | 224.8 |
| url | raw | [raw_urls_with_domain_v3.csv](raw_urls_with_domain_v3.csv) | 2,194,923 | 1,316,060 | 878,863 | 195.6 |
| url | features | [dataset_url_with_domain.csv](dataset_url_with_domain.csv) | 2,194,913 | 1,316,055 | 878,858 | 416.3 |

## Raw → feature → huấn luyện

Chạy từ thư mục `ML/`:

- Domain: `raw_domains_augmented.csv` → `python compile_dataset_domain.py` → `dataset_domain_augmented.csv` → `python train_domain_lgbm_model.py`.
- URL: `raw_urls_with_domain_v3.csv` → `python extract_full_url.py` → `dataset_url_with_domain.csv` → `python train_url_lgbm_model.py`.

Raw domain chứa hostname và nhãn; raw URL chứa URL, domain và nhãn. Bản feature domain có 26 đặc trưng; bản feature URL có 40 đặc trưng. Cột `domain` dùng để chia nhóm train/test, cột `label` là nhãn. Bản feature URL không giữ chuỗi URL gốc.

Thư mục `ML/` chỉ giữ bốn script cốt lõi cho extract feature và huấn luyện. Hai pipeline bên trên có đủ dataset đầu vào; các script tổng hợp dữ liệu nguồn, xử lý trung gian và thử nghiệm đã được xóa.

Các bước extract có thể bỏ qua dòng không xử lý được; số dòng raw và feature vì vậy có thể khác nhau. Chạy lại các script sẽ ghi đè đầu ra; cập nhật manifest nếu thay dataset.

## Manifest

[manifest.json](manifest.json) ghi lại schema, số dòng, phân bố nhãn, dung lượng và SHA-256 của từng file hiện tại. Manifest xác định bộ final mà không cần sao chép các CSV lớn.

Bộ dữ liệu được phân phối dưới dạng file đính kèm GitHub Release. Tải gói `url-safety-checker-dataset-v1.0.tar.gz` trong mục Assets và giải nén; thư mục `ML/` chứa dữ liệu cùng các script extract và huấn luyện.
