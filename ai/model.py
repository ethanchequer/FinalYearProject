"""
model.py

This module defines the AIModel class responsible for loading a trained machine learning model and making predictions
about the optimal PQC algorithm based on benchmarking test results. It also provides a method to extract relevant
features from test results for model input.
"""

import joblib  # Used for loading the pre-trained machine learning (ML) model from a Python pickle (.pkl) file

# Handles model loading, prediction, and feature extraction for PQC benchmarking
class AIModel:
    # Initialize the model by specifying the model path and loading it
    def __init__(self, model_path="model/optimal_algorithm_model_v2.pkl"):
        self.model_path = model_path
        self.model = self.load_model()

    # Load the trained ML model from the specified file path using joblib
    def load_model(self):
        return joblib.load(self.model_path)

    # Predict the most suitable PQC algorithm given a list of features
    def predict_optimal_algorithm(self, features):
        return self.model.predict([features])[0]

    # Extract numerical feature values (execution time, CPU, memory) from a test data dictionary
    def extract_features_from_test(self, test_data):
        """
        Expects a dict or object with keys:
        'execution_time', 'cpu_usage', 'memory_usage'
        """
        return [
            test_data.get("execution_time", 0),
            test_data.get("cpu_usage", 0),
            test_data.get("memory_usage", 0)
        ]
