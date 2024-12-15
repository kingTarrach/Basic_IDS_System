import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# 
#   Load Dataset
#

# Load the labeled dataset
data = pd.read_csv("labeled_traffic_data.csv")

# Binary encoding for labels
data["Label"] = data["Label"].map({"Normal": 0, "Anomalous": 1})

# Check and drop rows with missing labels
data = data.dropna(subset=["Label"])

# One-hot encode Protocol column
data = pd.get_dummies(data, columns=["Protocol"], drop_first=True)  

data["Length"] = pd.to_numeric(data["Length"], errors="coerce").fillna(-1)

# Vectorize the Info text field
vectorizer = TfidfVectorizer(max_features=100)  # Use top 100 terms
info_tfidf = vectorizer.fit_transform(data["Info"].fillna("")).toarray()

# Combine all features
X = pd.concat([pd.DataFrame(info_tfidf, columns=vectorizer.get_feature_names_out()), data[["Length"]], data.filter(regex="Protocol_")], axis=1)
# Response variable
y = data["Label"] # Map labels to 0 (Normal) and 1 (Anomalous)

# Handle missing values (if any) by filling with -1
X = X.fillna(-1)
y = y.fillna(1)

#
#   Create the model
#

# Split the dataset into training and testing sets (70% training, 30% testing)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

# Initialize the Random Forest Classifier
model = RandomForestClassifier(random_state=42, n_estimators=100, class_weight="balanced")

# Train the model on the training data
model.fit(X_train, y_train)

# Make predictions on the test set
y_pred = model.predict(X_test)

#
#   Evaluate ML algorithm
#

# Print classification metrics
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("Classification Report:")
print(classification_report(y_test, y_pred))

# Visualize the confusion matrix
plt.figure(figsize=(8, 6))
sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt="d", cmap="Blues", xticklabels=["Normal", "Anomalous"], yticklabels=["Normal", "Anomalous"])
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
# plt.show()

#
#   Save the model
# 


