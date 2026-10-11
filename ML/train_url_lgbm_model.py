import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from onnxmltools.convert.lightgbm.operator_converters.LightGbm import convert_lightgbm
from skl2onnx import convert_sklearn, update_registered_converter
from skl2onnx.common.data_types import FloatTensorType
from skl2onnx.common.shape_calculator import calculate_linear_classifier_output_shapes

BASE = './dataset/'
df = pd.read_csv(f'{BASE}dataset_url_with_domain.csv')
print(f"Tổng số dòng: {len(df)}")
print(f"Tổng số domain duy nhất: {df['domain'].nunique()}")

X = df.drop(columns=['domain', 'label'])
y = df['label']
groups = df['domain']

gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
domain_train = set(groups.iloc[train_idx])
domain_test = set(groups.iloc[test_idx])
print(f"Số domain bị trùng giữa train/test (phải = 0): {len(domain_train & domain_test)}")

print("Train label distribution:")
print(y_train.value_counts(normalize=True))
print("Test label distribution:")
print(y_test.value_counts(normalize=True))

neg = (y_train == 0).sum()
pos = (y_train == 1).sum()
spw = neg / pos
print(f"\nscale_pos_weight (tính trên train set): {spw:.4f}")
print(f"Features: {len(X.columns)}")

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

print("=" * 50)
print("CLASSIFICATION REPORT (group split theo domain)")
print("=" * 50)
print(report)

print("=" * 50)
print("CONFUSION MATRIX")
print("=" * 50)
print(f"                Predicted Phishing  Predicted Safe")
print(f"Actual Phishing {cm[0][0]:<20} {cm[0][1]}")
print(f"Actual Safe     {cm[1][0]:<20} {cm[1][1]}")
print(f"\nROC AUC Score: {auc_score:.4f}")

importances_raw = list(zip(X.columns, model.feature_importances_))
total = sum(imp for _, imp in importances_raw)
importances = sorted([(f, i/total) for f, i in importances_raw], key=lambda x: x[1], reverse=True)

print("=" * 50)
print("FEATURE IMPORTANCE")
print("=" * 50)
for feat, imp in importances:
    bar = '█' * int(imp * 100)
    print(f"{feat:<35} {imp:.4f} {bar}")

# False negatives/positives để soi
X_test_copy = X_test.copy()
X_test_copy['domain'] = groups.iloc[test_idx].values
X_test_copy['actual'] = y_test.values
X_test_copy['pred'] = y_pred
X_test_copy['pred_prob_safe'] = y_prob

fn = X_test_copy[(X_test_copy['actual']==0) & (X_test_copy['pred']==1)].sort_values('pred_prob_safe', ascending=False)
fp = X_test_copy[(X_test_copy['actual']==1) & (X_test_copy['pred']==0)].sort_values('pred_prob_safe', ascending=True)

print(f"\n=== FALSE NEGATIVES: {len(fn)} URL phishing bị đoán nhầm Safe ===")
print(fn[['domain','pred_prob_safe']].head(40).to_string(index=False))
fn.to_csv(f'{BASE}url_false_negatives_review.csv', index=False)

print(f"\n=== FALSE POSITIVES: {len(fp)} URL an toàn bị đoán nhầm Phishing ===")
print(fp[['domain','pred_prob_safe']].head(40).to_string(index=False))
fp.to_csv(f'{BASE}url_false_positives_review.csv', index=False)

# Export ONNX
n_features = len(X.columns)
update_registered_converter(
    lgb.LGBMClassifier, "LightGbmLGBMClassifier",
    calculate_linear_classifier_output_shapes, convert_lightgbm,
    options={"nocl": [True, False], "zipmap": [True, False]}
)
initial_type = [('float_input', FloatTensorType([None, n_features]))]
onnx_model = convert_sklearn(
    model, initial_types=initial_type,
    options={id(model): {'zipmap': False}},
    target_opset={'': 15, 'ai.onnx.ml': 3}
)
with open('./model_url_v2.onnx', 'wb') as f:
    f.write(onnx_model.SerializeToString())
print("\nExported model_url_v2.onnx")