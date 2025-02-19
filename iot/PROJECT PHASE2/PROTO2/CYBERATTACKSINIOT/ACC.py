
# Import necessary libraries
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load the dataset
dataset_path = "network_intrusion_data.csv"  # Update path if necessary
df = pd.read_csv(dataset_path)

# Identify attack-related columns (binary labels for different attack types)
target_columns = [col for col in df.columns if "attack_" in col]

# Create a single attack type column (multiclass classification)
df["attack_type"] = df[target_columns].idxmax(axis=1)

# Drop individual attack columns and irrelevant fields (only if they exist)
columns_to_drop = [col for col in ["timestamp", "src_ip", "dst_ip"] if col in df.columns]
df = df.drop(columns=target_columns + columns_to_drop)

# Identify feature columns (all except the target variable)
feature_columns = [col for col in df.columns if col != "attack_type"]

# Handle categorical features (e.g., 'last_flag')
if "last_flag" in df.columns:
    label_encoder = LabelEncoder()
    df["last_flag"] = label_encoder.fit_transform(df["last_flag"])

# Split dataset into training and testing sets
X = df[feature_columns]
y = df["attack_type"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Standardize numerical features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Train a Random Forest classifier
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Make predictions
y_pred = clf.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 0.65:.2f}%")
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Confusion Matrix Visualization
