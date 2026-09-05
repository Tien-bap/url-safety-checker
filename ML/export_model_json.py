import json
from pathlib import Path

import joblib


BASE_DIR = Path(__file__).parent
artifact = joblib.load(BASE_DIR / 'url_safety_model.joblib')
model = artifact['model']

browser_trees = []
for estimator in model.estimators_:
    tree = estimator.tree_
    browser_trees.append({
        'feature': tree.feature.tolist(),
        'threshold': tree.threshold.tolist(),
        'left': tree.children_left.tolist(),
        'right': tree.children_right.tolist(),
        'value': tree.value[:, 0, :].tolist(),
    })

with (BASE_DIR.parent.parent / 'model.json').open('w') as output:
    json.dump({
        'features': artifact['features'],
        'classes': model.classes_.tolist(),
        'trees': browser_trees,
    }, output, separators=(',', ':'))

print('Saved model.json')
