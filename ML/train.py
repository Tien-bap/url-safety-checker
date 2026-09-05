import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType as OnnxFloatTensorType
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from skl2onnx import convert_sklearn, update_registered_converter
from skl2onnx.common.data_types import FloatTensorType
from skl2onnx.common.shape_calculator import calculate_linear_classifier_output_shapes
from onnxmltools.convert.lightgbm.operator_converters.LightGbm import convert_lightgbm

df = pd.read_csv("./dataset_final.csv")
X = df.drop(columns=['label'])
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = lgb.LGBMClassifier(
    n_estimators=200,
    learning_rate=0.05,
    num_leaves=63,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scores = cross_validate(
    model, X, y,
    cv=kfold,
    scoring=['accuracy', 'precision_macro', 'recall_macro', 'f1_macro', 'roc_auc'],
    n_jobs=1
)

print("=" * 50)
print("K-FOLD CROSS VALIDATION (k=5)")
print("=" * 50)
for metric, values in scores.items():
    if metric.startswith('test_'):
        name = metric.replace('test_', '')
        print(f"{name:<20} {values.mean():.4f} ± {values.std():.4f}")
        print(f"{'':20} per fold: {[f'{v:.4f}' for v in values]}")
        print()

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

report = classification_report(y_test, y_pred, target_names=['Safe', 'Phishing'])
cm = confusion_matrix(y_test, y_pred)
auc_score = roc_auc_score(y_test, y_prob)

importances_raw = list(zip(X.columns, model.feature_importances_))
total = sum(imp for _, imp in importances_raw)
importances = sorted(
    [(feat, imp/total) for feat, imp in importances_raw],
    key=lambda x: x[1], reverse=True
)

print("=" * 50)
print("CLASSIFICATION REPORT")
print("=" * 50)
print(report)

print("=" * 50)
print("CONFUSION MATRIX")
print("=" * 50)
print(f"                Predicted Safe  Predicted Phishing")
print(f"Actual Safe     {cm[0][0]:<15} {cm[0][1]}")
print(f"Actual Phishing {cm[1][0]:<15} {cm[1][1]}")
print(f"\nROC AUC Score: {auc_score:.4f}")

print("=" * 50)
print("FEATURE IMPORTANCE")
print("=" * 50)
for feat, imp in importances:
    bar = '█' * int(imp * 100)
    print(f"{feat:<35} {imp:.4f} {bar}")

# Export ONNX
update_registered_converter(
    lgb.LGBMClassifier,
    "LightGbmLGBMClassifier",
    calculate_linear_classifier_output_shapes,
    convert_lightgbm,
    options={"nocl": [True, False], "zipmap": [True, False]}
)
initial_type = [('float_input', FloatTensorType([None, 35]))]
onnx_model = convert_sklearn(
    model,
    initial_types=initial_type,
    options={id(model): {'zipmap': False}},
    target_opset={'': 15, 'ai.onnx.ml': 3}
)
with open('model_lgbm.onnx', 'wb') as f:
    f.write(onnx_model.SerializeToString())
print("Exported!")