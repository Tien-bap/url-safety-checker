import pandas as pd
import numpy as np
import tldextract
import lightgbm as lgb
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from skl2onnx import convert_sklearn, update_registered_converter
from skl2onnx.common.data_types import FloatTensorType
from skl2onnx.common.shape_calculator import calculate_linear_classifier_output_shapes
from onnxmltools.convert.lightgbm.operator_converters.LightGbm import convert_lightgbm

# ========== Load dữ liệu ==========
# LƯU Ý: cần cột 'domain' để group theo apex và để in false negative dễ đọc.
# Nếu dataset_domain_final.csv không còn giữ cột domain gốc, cần export lại
# kèm domain (không chỉ feature) từ bước extract để phục vụ debug.
df = pd.read_csv("./dataset/dataset_domain_augmented.csv")

if 'domain' not in df.columns:
    raise ValueError(
        "Thiếu cột 'domain' trong dataset_domain_augmented.csv — "
        "cần export lại kèm domain gốc để group-split và debug false negative."
    )

FEATURE_COLS = [c for c in df.columns if c not in ('label', 'domain')]
X = df[FEATURE_COLS]
y = df['label']

# ========== Group key: apex domain (registered_domain + suffix) ==========
def get_apex(hostname):
    ext = tldextract.extract(str(hostname))
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

df['apex_group'] = df['domain'].apply(get_apex)
groups = df['apex_group']

print(f"Tổng số dòng: {len(df)}")
print(f"Tổng số apex domain duy nhất: {groups.nunique()}")

# ========== Group split — đảm bảo cùng apex không lẫn cả train và test ==========
gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups=groups))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
domain_test = df['domain'].iloc[test_idx].reset_index(drop=True)

# Sanity check: không có apex nào lẫn cả 2 tập
train_apex = set(groups.iloc[train_idx])
test_apex = set(groups.iloc[test_idx])
overlap = train_apex & test_apex
print(f"Số apex bị trùng giữa train/test (phải = 0): {len(overlap)}")

# Kiểm tra tỷ lệ class sau khi split theo group (không stratify được chính xác
# như stratify=y thông thường, nên cần in ra để xác nhận không bị lệch quá mức)
print(f"Train label distribution:\n{y_train.value_counts(normalize=True)}")
print(f"Test label distribution:\n{y_test.value_counts(normalize=True)}")

# ========== Train ==========
neg = len(y_train[y_train == 0])
pos = len(y_train[y_train == 1])
spw = neg / pos
print(f"\nscale_pos_weight (tính trên train set): {spw:.4f}")
print(f"Features: {len(FEATURE_COLS)} — {FEATURE_COLS}")

model = lgb.LGBMClassifier(
    n_estimators=500,
    learning_rate=0.05,
    num_leaves=127,
    scale_pos_weight=spw,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

report = classification_report(y_test, y_pred, target_names=['Phishing', 'Safe'])
cm = confusion_matrix(y_test, y_pred)
auc_score = roc_auc_score(y_test, y_prob)

importances_raw = list(zip(FEATURE_COLS, model.feature_importances_))
total = sum(imp for _, imp in importances_raw)
importances = sorted(
    [(feat, imp / total) for feat, imp in importances_raw],
    key=lambda x: x[1], reverse=True
)

print("=" * 50)
print("CLASSIFICATION REPORT (group split theo apex domain)")
print("=" * 50)
print(report)

print("=" * 50)
print("CONFUSION MATRIX")
print("=" * 50)
print(f"                Predicted Phishing  Predicted Safe")
print(f"Actual Phishing {cm[0][0]:<20} {cm[0][1]}")
print(f"Actual Safe     {cm[1][0]:<20} {cm[1][1]}")
print(f"\nROC AUC Score: {auc_score:.4f}")

print("=" * 50)
print("FEATURE IMPORTANCE")
print("=" * 50)
for feat, imp in importances:
    bar = '█' * int(imp * 100)
    print(f"{feat:<35} {imp:.4f} {bar}")

# ========== Phân tích False Negative (phishing bị đoán nhầm Safe) ==========
result_df = X_test.copy()
result_df['domain'] = domain_test.values
result_df['true_label'] = y_test.values
result_df['pred_label'] = y_pred
result_df['pred_prob_safe'] = y_prob

false_negatives = result_df[
    (result_df['true_label'] == 0) & (result_df['pred_label'] == 1)
].sort_values('pred_prob_safe', ascending=False)  # domain phishing mà model "tự tin" nhất là Safe

print("=" * 50)
print(f"FALSE NEGATIVES: {len(false_negatives)} domain phishing bị đoán nhầm Safe")
print("=" * 50)
print(false_negatives[['domain', 'pred_prob_safe', 'EntropyRegisteredDomain',
                        'DomainLength', 'MinBrandLevenshteinDistanceNormalized']]
      .head(40).to_string(index=False))

false_negatives.to_csv('./dataset/false_negatives_review.csv', index=False)
print("\nĐã lưu toàn bộ false negatives vào dataset/false_negatives_review.csv để xem thêm")

# ========== Phân tích False Positive (safe bị đoán nhầm phishing) — cũng nên xem ==========
false_positives = result_df[
    (result_df['true_label'] == 1) & (result_df['pred_label'] == 0)
].sort_values('pred_prob_safe', ascending=True)

print("=" * 50)
print(f"FALSE POSITIVES: {len(false_positives)} domain an toàn bị đoán nhầm phishing")
print("=" * 50)
print(false_positives[['domain', 'pred_prob_safe']].head(40).to_string(index=False))
false_positives.to_csv('./dataset/false_positives_review.csv', index=False)

# ========== Export ONNX ==========
n_features = len(FEATURE_COLS)
update_registered_converter(
    lgb.LGBMClassifier,
    "LightGbmLGBMClassifier",
    calculate_linear_classifier_output_shapes,
    convert_lightgbm,
    options={"nocl": [True, False], "zipmap": [True, False]}
)
initial_type = [('float_input', FloatTensorType([None, n_features]))]
onnx_model = convert_sklearn(
    model,
    initial_types=initial_type,
    options={id(model): {'zipmap': False}},
    target_opset={'': 15, 'ai.onnx.ml': 3}
)
with open('./model_domain.onnx', 'wb') as f:
    f.write(onnx_model.SerializeToString())
print(f"Exported model_domain.onnx ({n_features} features)")