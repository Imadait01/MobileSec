"""
Simple training script for small datasets
"""
import sys
import os
import pandas as pd
import numpy as np
import lightgbm as lgb
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Load data
df = pd.read_csv('/app/data/security_scan_dataset.csv')
print(f"Loaded {len(df)} scans")

# Define features
feature_cols = [
    'crypto_total_vulns', 'crypto_high', 'crypto_medium', 'crypto_low', 'crypto_info',
    'crypto_weak_cipher', 'crypto_weak_hash', 'crypto_insecure_random', 'crypto_weak_rsa',
    'crypto_unique_cwes', 'secrets_count', 'secrets_api_keys', 'secrets_passwords',
    'secrets_tokens', 'secrets_aws_keys', 'secrets_other', 'secrets_unique_types',
    'network_findings', 'network_endpoints', 'network_http_issues',
    'network_cert_issues', 'network_domain_issues', 'total_vulnerabilities', 'severity_score'
]

X = df[feature_cols].values
y_raw = df['fix_category'].values

# Encode labels
le = LabelEncoder()
y = le.fit_transform(y_raw)

print(f"Classes: {le.classes_}")
print(f"Class distribution: {np.bincount(y)}")

# Simple split (not stratified due to imbalanced classes)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Scale features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

print(f"Train: {len(X_train)}, Test: {len(X_test)}")

# Train LightGBM
train_data =lgb.Dataset(X_train, label=y_train)
params = {
    'objective': 'multiclass',
    'num_class': len(le.classes_),
    'metric': 'multi_logloss',
    'boosting_type': 'gbdt',
    'num_leaves': 15,  # Reduced for small dataset
    'learning_rate': 0.1,
    'feature_fraction': 0.8,
    'verbose': -1,
}

model = lgb.train(params, train_data, num_boost_round=100)

# Evaluate
y_pred = model.predict(X_test)
y_pred_class = np.argmax(y_pred, axis=1)

accuracy = accuracy_score(y_test, y_pred_class)
print(f"\nTest Accuracy: {accuracy:.4f}")

# Save model
os.makedirs('/app/models', exist_ok=True)
model.save_model('/app/models/lightgbm_model.txt')
joblib.dump(le, '/app/models/label_encoder.pkl')
joblib.dump(scaler, '/app/models/feature_scaler.pkl')

print("\n✅ Model trained and saved")
print(f"   Model: /app/models/lightgbm_model.txt")
print(f"   Accuracy: {accuracy:.2%}")
