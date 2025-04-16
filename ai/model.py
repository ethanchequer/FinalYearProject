import joblib

class AIModel:
    def __init__(self, model_path="model/optimal_algorithm_model_v2.pkl"):
        self.model_path = model_path
        self.model = self.load_model()

    def load_model(self):
        return joblib.load(self.model_path)

    def predict_optimal_algorithm(self, features):
        return self.model.predict([features])[0]

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
