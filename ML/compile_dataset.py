import requests
import hashlib
import pandas as pd
from extract import extract_features, FEATURE_NAMES  # import từ file extract.py

# ========== 1. Load dataset_custom.csv (đã có) ==========
df_phiusiil = pd.read_csv('./dataset_custom.csv')
print(f"PhiUSIIL: {len(df_phiusiil)} URLs")
print(df_phiusiil['label'].value_counts())

# ========== 2. Blacklist URLs (label 0 = phishing) ==========
blacklist_urls = set()

# OpenPhish
try:
    res = requests.get("https://openphish.com/feed.txt", timeout=10)
    urls = [l.strip() for l in res.text.splitlines() if l.strip() and not l.startswith('#')]
    blacklist_urls.update(urls)
    print(f"OpenPhish: {len(urls)} URLs")
except Exception as e:
    print(f"OpenPhish failed: {e}")

# URLhaus
try:
    res = requests.get("https://urlhaus.abuse.ch/downloads/text/", timeout=10)
    urls = [l.strip() for l in res.text.splitlines() if l.strip() and not l.startswith('#')]
    blacklist_urls.update(urls)
    print(f"URLhaus: {len(urls)} URLs")
except Exception as e:
    print(f"URLhaus failed: {e}")

print(f"Tổng blacklist (unique): {len(blacklist_urls)} URLs")

# Extract features cho blacklist
rows_blacklist = []
for url in blacklist_urls:
    f = extract_features(url)
    if f:
        rows_blacklist.append(f + [0])  # label 0 = phishing

df_blacklist = pd.DataFrame(rows_blacklist, columns=FEATURE_NAMES + ['label'])
print(f"Blacklist extracted: {len(df_blacklist)} URLs")

# Thay đoạn Tranco trong script bằng:
df_tranco_raw = pd.read_csv('./top-1m.csv', header=None, names=['rank', 'domain'])
domains = df_tranco_raw['domain'].tolist()

# Lấy số lượng tương đương blacklist để cân bằng
sample_size = len(df_blacklist)
domains = domains[:sample_size]
tranco_urls = ['https://' + d for d in domains]
print(f"Tranco: {len(tranco_urls)} domains")


# Extract features cho Tranco
rows_tranco = []
for url in tranco_urls:
    f = extract_features(url)
    if f:
        rows_tranco.append(f + [1])  # label 1 = safe

df_tranco = pd.DataFrame(rows_tranco, columns=FEATURE_NAMES + ['label'])
print(f"Tranco extracted: {len(df_tranco)} URLs")

# ========== 4. Merge tất cả ==========
df_final = pd.concat([df_phiusiil, df_blacklist, df_tranco], ignore_index=True)  # df_tranco không phải df_tranco_raw
df_final = df_final.sample(frac=1, random_state=42)


print("\n=== TỔNG KẾT ===")
print(f"Tổng: {len(df_final)} URLs")
print(df_final['label'].value_counts())

df_final.to_csv('dataset_final.csv', index=False)
print("Đã lưu dataset_final.csv")


