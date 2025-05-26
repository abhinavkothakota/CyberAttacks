import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, classification_report

# ✅ Load Model
model = joblib.load("model.pkl")

# ✅ Load Test Dataset
df = pd.read_csv("network_intrusion_data.csv")

# ✅ Ensure 'last_flag' is properly encoded
df['last_flag'] = df['last_flag'].astype('category').cat.codes  # Convert to numeric

# ✅ Define Features (Ensure they match model training)
feature_columns = [
    'attack_neptune', 'attack_normal', 'attack_satan', 'count',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_same_srv_rate', 'dst_host_srv_count', 'flag_S0', 'flag_SF',
    'logged_in', 'same_srv_rate', 'serror_rate', 'service_http', 'last_flag'
]

# ✅ Extract Features & Labels
X_test = df[feature_columns]
y_true = df['attack_normal']  # Change this if the label column is different

# ✅ Ensure feature names match model training order
X_test = X_test[model.feature_names_in_]

# ✅ Make Predictions
y_pred = model.predict(X_test)

# ✅ Ensure y_pred matches y_true length
y_pred = y_pred[:len(y_true)]

# ✅ Get Unique Class Labels
unique_classes = sorted(set(y_true.unique()) | set(y_pred))  # Unique values in y_true & y_pred
print("Unique Classes:", unique_classes)  # Debugging

# ✅ Generate Class Labels Dynamically
target_names = [f"Class {c}" for c in unique_classes]  # Create class names dynamically

# ✅ Compute Accuracy
accuracy = accuracy_score(y_true, y_pred)

# ✅ Generate Classification Report with Correct Labels
classification_rep = classification_report(y_true, y_pred, labels=unique_classes, target_names=target_names)

# ✅ Print Results
print(f"Model Accuracy: {accuracy * 1000:.2f}%")
print("\nClassification Report:\n", classification_rep)