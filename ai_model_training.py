DEBUG = True  # Set to false to disable debug output

def debug_print(message):
    if DEBUG:
        print(f"[DEBUG] {message}")

# Step 1: Import Necessary Libraries
import pandas as pd # for data manipulation
import numpy as np # for handling numeric operations
from sklearn.model_selection import train_test_split # sklearn for building and evaluating the decision tree model
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt # for visualizing the decision tree
import joblib

# Step 2: Load the dataset
debug_print("Loading the dataset...")
df = pd.read_csv("data/results_dataset.csv") # load "pqc_dataset.csv" in pandas dataframe
debug_print(f"Dataset loaded. Shape: {df.shape}")
debug_print(f"Columns in dataset: {df.columns.tolist()}")
print(df.head())  # Display basic info

# Step 3: Preprocess the data
debug_print("Preprocessing data...")

# Create new features based on algorithm and application
df['security_weighting'] = df['algorithm'].map({
    'Kyber512': 1,
    'Dilithium2': 2,
    'SPHINCS+-SHA2-128s': 1
})
debug_print("Added security_weighting feature based on algorithm.")

# Add application importance based on application type
df['application_importance'] = df['application'].map({
    'Web Browsing': 1,
    'VoIP': 2,
    'Video Streaming': 3,
    'File Transfer': 4
})
debug_print("Added application_importance feature based on application type.")

# Encode categorical variables using One-Hot Encoding
df = pd.get_dummies(df, columns=["algorithm", "application"])
debug_print("Categorical variables encoded.")

# Drop unnecessary columns
df = df.drop(["id", "timestamp"], axis=1)
debug_print("Dropped unnecessary columns.")

# Handle missing values
df['memory_usage'] = pd.to_numeric(df['memory_usage'], errors='coerce').fillna(df['memory_usage'].median())
df['avg_throughput_kbps'] = pd.to_numeric(df['avg_throughput_kbps'], errors='coerce').fillna(df['avg_throughput_kbps'].median())
debug_print("Handled missing values for memory usage and throughput.")
df['packet_completion_rate'] = df['packets_sent'] / df['packet_count_requested']
debug_print("Calculated packet completion rate as packets_sent / packet_count_requested.")

def safe_numeric(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0

def assign_optimal_algorithm(row):
    # Safely convert each metric to a numeric value
    throughput_efficiency = safe_numeric(row["throughput_efficiency_kbps"])
    cpu_efficiency = safe_numeric(row["cpu_efficiency"])
    latency_ratio = safe_numeric(row["latency_to_throughput_ratio"])
    security_weighting = safe_numeric(row["security_weighting"])

    # Calculate a score for each algorithm based on weighted factors
    scores = {
        "Kyber512": throughput_efficiency * 0.3 + cpu_efficiency * 0.2 + latency_ratio * 0.2 + security_weighting * 0.3,
        "Dilithium2": throughput_efficiency * 0.25 + cpu_efficiency * 0.25 + latency_ratio * 0.2 + security_weighting * 0.3,
        "SPHINCS+-SHA2-128s": throughput_efficiency * 0.2 + cpu_efficiency * 0.2 + latency_ratio * 0.2 + security_weighting * 0.4,
    }
    # Return the algorithm with the highest score
    result = max(scores, key=scores.get)
    # Construct the application name from one-hot encoded columns
    application_name = [col.replace('application_', '') for col in row.index if col.startswith('application_') and row[col] == 1 and col != 'application_importance']
    if application_name:
        application_name = application_name[0]
    else:
        application_name = "Unknown"
    debug_print(f"Assigned optimal algorithm '{result}' for application: {application_name}")
    return result

# Apply the function to each row to populate the optimal_algorithm column
df["optimal_algorithm"] = df.apply(assign_optimal_algorithm, axis=1)
debug_print("Automatically assigned optimal algorithm for each record.")
debug_print("Optimal algorithm assignment complete.")

# Feature scaling
features = [col for col in df.columns if col != "optimal_algorithm"]
features.append('latency_per_test')
debug_print(f"Updated features to include latency per test: {features}")
features.append('packet_completion_rate')
debug_print(f"Updated features to include packet_completion_rate: {features}")

# Include new features in the feature list
features.append('security_weighting')
features.append('application_importance')
debug_print(f"Updated features used for training: {features}")

scaler = StandardScaler()
df[features] = scaler.fit_transform(df[features])
debug_print("Scaled features.")
# Scales numerical features to have a mean of 0 and a standard deviation of 1

# Step 4: Prepare Features and Target
debug_print("Preparing features and target...")
y = df["optimal_algorithm"] # optimal_algorithm is the target variable

# Drop the target column from the feature set
X = df.drop("optimal_algorithm", axis=1)
debug_print(f"Features before training: {list(X.columns)}")

debug_print(f"Feature set shape: {X.shape}")
debug_print(f"Target shape: {y.shape}")

# Split data into training and testing sets (70-30 split)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
debug_print("Data split into training and testing sets.")
debug_print(f"Training set shape: X_train={X_train.shape}, y_train={y_train.shape}")
debug_print(f"Testing set shape: X_test={X_test.shape}, y_test={y_test.shape}")

# Step 5: Train the Decision Tree Classifier
debug_print("Training the Decision Tree model...")
# Create the model with adjusted parameters
model = DecisionTreeClassifier(criterion="gini", max_depth=15, random_state=42)
debug_print("Model created with updated criterion and max_depth.")

# Train the model
model.fit(X_train, y_train)
debug_print("Model training complete.")
debug_print(f"Features used during training: {list(X.columns)}")

# Save the model
model_filename = "model/optimal_algorithm_model_v2.pkl"
joblib.dump(model, model_filename)
debug_print(f"Model saved to {model_filename}.")

# Predict on the test set
debug_print("Making predictions on the test set...")
y_pred = model.predict(X_test)
debug_print("Predictions made successfully.")
debug_print(f"Sample predictions: {y_pred[:5]}")

# Step 6: Evaluate the Model
accuracy = accuracy_score(y_test, y_pred) * 100
debug_print(f"Model accuracy: {accuracy:.2f}%")
print(f"Accuracy: {accuracy:.2f}%")
print("Classification Report:")
print(classification_report(y_test, y_pred))
debug_print("Evaluation complete. Model performance summary:")
debug_print(f"Accuracy: {accuracy:.2f}%")
debug_print("Analyzing the impact of new features on accuracy...")

# Additional debug statements can be added to assess the importance of new features if needed

# Step 6: Visualize the Decision Tree
debug_print("Visualizing the decision tree...")
plt.figure(figsize=(20, 10))
plot_tree(model, feature_names=X.columns, class_names=y.unique(), filled=True)
plt.show()
debug_print("Visualization complete.")