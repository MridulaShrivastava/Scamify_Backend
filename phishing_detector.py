import pandas as pd
import joblib
import os
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_selection import SelectFromModel
from imblearn.over_sampling import SMOTE
from sklearn.metrics import accuracy_score, classification_report

# ✅ Load Dataset
file_path = "dataset/dataset_full.csv"
if not os.path.exists(file_path):
    raise FileNotFoundError(f"⚠️ Dataset not found at: {file_path}")

df = pd.read_csv(file_path)
print("✅ Dataset Loaded Successfully!")

# ✅ Drop 'Index' if exists
df.drop(columns=['Index'], errors='ignore', inplace=True)

# ✅ Check target column
target_column = 'phishing'
if target_column not in df.columns:
    raise KeyError(f"⚠️ Target column '{target_column}' not found!")

# ✅ Split Features and Target
X = df.drop(columns=[target_column])
y = df[target_column]

# ✅ Check Class Distribution Before SMOTE
class_counts = Counter(y)
print(f"⚖️ Class Distribution Before SMOTE: {class_counts}")

# ✅ Apply SMOTE Properly
smote = SMOTE(sampling_strategy="not majority", random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)

# ✅ Check Class Distribution After SMOTE
new_counts = Counter(y_resampled)
print(f"✅ Class Distribution After SMOTE: {new_counts}")

# ✅ Feature Selection
rf_selector = RandomForestClassifier(n_estimators=100, random_state=42)
rf_selector.fit(X_resampled, y_resampled)

# ✅ Select Features
selector = SelectFromModel(rf_selector, threshold=-1, prefit=True)
X_selected = selector.transform(X_resampled)
selected_feature_names = X.columns[selector.get_support()].tolist()

# ✅ Print Number of Selected Features
print(f"✅ Initially Selected Features: {len(selected_feature_names)} features")

# ✅ Ensure Exactly 37 Features
if len(selected_feature_names) > 37:
    selected_feature_names = selected_feature_names[:37]  # Trim extra features
elif len(selected_feature_names) < 37:
    raise ValueError(f"⚠️ Only {len(selected_feature_names)} features selected, expected 37!")

print(f"✅ Final Selected Features: {len(selected_feature_names)} features")
print(selected_feature_names)

# ✅ Save Selected Features
joblib.dump(selected_feature_names, "feature_names.pkl")
print("✅ Selected Features Saved!")

# ✅ Train-Test Split (20% Test Data)
X_train, X_test, y_train, y_test = train_test_split(
    X_resampled[selected_feature_names], y_resampled, test_size=0.2, random_state=42
)

# ✅ Train Final Model
rf_model = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
rf_model.fit(X_train, y_train)

# ✅ Feature Importance Plot
feature_importance = rf_model.feature_importances_
sorted_idx = np.argsort(feature_importance)[::-1]  # Sort in descending order

plt.figure(figsize=(12, 6))
plt.barh(np.array(selected_feature_names)[sorted_idx], feature_importance[sorted_idx], color='royalblue')
plt.xlabel("Feature Importance")
plt.ylabel("Features")
plt.title("Random Forest Feature Importance")
plt.gca().invert_yaxis()  # Highest importance on top
plt.show()

# ✅ Print Top 10 Features
print("\n📊 Top 10 Important Features:")
for i in range(10):
    print(f"{selected_feature_names[sorted_idx[i]]}: {feature_importance[sorted_idx[i]]:.4f}")

# ✅ Cross Validation to Check Overfitting
cv_scores = cross_val_score(rf_model, X_train, y_train, cv=5)
print(f"🎯 Cross-Validation Accuracy: {cv_scores.mean():.4f}")

# ✅ Check Model Performance
y_pred_train = rf_model.predict(X_train)
y_pred_test = rf_model.predict(X_test)

train_accuracy = accuracy_score(y_train, y_pred_train)
test_accuracy = accuracy_score(y_test, y_pred_test)

print(f"🏆 Train Accuracy: {train_accuracy:.4f}")
print(f"🧪 Test Accuracy: {test_accuracy:.4f}")

# ✅ Print Classification Report (Check Balance)
print("\n📊 Classification Report on Test Data:\n", classification_report(y_test, y_pred_test))

# ✅ Save Model
joblib.dump(rf_model, "phishing_model.pkl")
print("✅ Model Saved Successfully!")
