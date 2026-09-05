from pathlib import Path
from collections import Counter
from urllib.parse import urlsplit
import ipaddress
import math
import re

import joblib
import pandas as pd


MODEL_PATH = Path(__file__).with_name('url_safety_model.joblib')
_artifact = joblib.load(MODEL_PATH)
model = _artifact['model']
URL_FEATURES = _artifact['features']


COMMON_TLDS = {
    'com': 0.95, 'org': 0.95, 'net': 0.90, 'edu': 0.98, 'gov': 0.98,
    'vn': 0.90, 'uk': 0.90, 'de': 0.90, 'jp': 0.90, 'io': 0.75,
}


def extract_features(url: str) -> dict:
    """Extract the 24 features expected by the saved PhiUSIIL model."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError('URL must be a non-empty string')

    normalized_url = url.strip()
    parsed = urlsplit(normalized_url if '://' in normalized_url else f'https://{normalized_url}')
    domain = parsed.hostname or ''
    if not domain:
        raise ValueError('URL does not contain a valid domain')

    path_and_query = f'{parsed.path}{parsed.query}'
    url_length = len(normalized_url)
    domain_length = len(domain)
    tld = domain.rsplit('.', 1)[-1].lower() if '.' in domain else ''
    letters = sum(character.isalpha() for character in normalized_url)
    digits = sum(character.isdigit() for character in normalized_url)
    special_characters = sum(not character.isalnum() for character in normalized_url)
    character_counts = Counter(normalized_url.lower())
    entropy = -sum(
        (count / max(url_length, 1)) * math.log2(count / max(url_length, 1))
        for count in character_counts.values()
    )
    max_continuation = max(
        (len(match.group()) for match in re.finditer(r'[A-Za-z0-9]+', normalized_url)),
        default=0,
    )
    subdomain_count = max(domain.count('.') - 1, 0)
    obfuscated_characters = len(re.findall(r'%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}', normalized_url))
    special_symbols = set('!?@#$%^&*()_=+[]{}|;:,<>`~\\"\'')
    other_specials = sum(character in special_symbols for character in normalized_url)
    keyword_text = f'{domain} {path_and_query}'.lower()

    try:
        ipaddress.ip_address(domain)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    return {
        'URLLength': url_length,
        'DomainLength': domain_length,
        'IsDomainIP': is_domain_ip,
        'TLDLength': len(tld),
        'CharContinuationRate': max_continuation / max(url_length, 1),
        'TLDLegitimateProb': COMMON_TLDS.get(tld, 0.50),
        'URLCharProb': entropy / 8,
        'NoOfSubDomain': subdomain_count,
        'HasObfuscation': int(obfuscated_characters > 0),
        'NoOfObfuscatedChar': obfuscated_characters,
        'ObfuscationRatio': obfuscated_characters / max(url_length, 1),
        'NoOfLettersInURL': letters,
        'LetterRatioInURL': letters / max(url_length, 1),
        'NoOfDegitsInURL': digits,
        'DegitRatioInURL': digits / max(url_length, 1),
        'NoOfEqualsInURL': normalized_url.count('='),
        'NoOfQMarkInURL': normalized_url.count('?'),
        'NoOfAmpersandInURL': normalized_url.count('&'),
        'NoOfOtherSpecialCharsInURL': other_specials,
        'SpacialCharRatioInURL': special_characters / max(url_length, 1),
        'IsHTTPS': int(parsed.scheme.lower() == 'https'),
        'Bank': int('bank' in keyword_text),
        'Pay': int('pay' in keyword_text),
        'Crypto': int(any(word in keyword_text for word in ('crypto', 'bitcoin', 'wallet'))),
    }


def predict(features: dict | str) -> dict:
    """Predict from a URL string or a pre-extracted feature dictionary."""
    if isinstance(features, str):
        features = extract_features(features)

    missing = [name for name in URL_FEATURES if name not in features]
    if missing:
        raise ValueError(f'Missing features: {", ".join(missing)}')

    values = pd.DataFrame(
        [[features[name] for name in URL_FEATURES]],
        columns=URL_FEATURES,
    )
    prediction = int(model.predict(values)[0])
    probability = float(model.predict_proba(values)[0][prediction])
    return {
        'label': prediction,
        'name': 'Phishing' if prediction == 1 else 'Safe',
        'probability': probability,
    }


url = input("Enter a URL to predict: ").strip()
features = extract_features(url)
result = predict(features)
print(f"Prediction: {result['name']} (label={result['label']}, probability={result['probability']:.4f})")