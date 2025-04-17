from benchmark.packet_analyzer import PacketAnalyzer
from benchmark.traffic_simulator import TrafficSimulator
from database.db_manager import get_db_connection
from ai.model import AIModel
import time
import psutil
import tracemalloc

class BenchmarkManager:
    def __init__(self, algorithm, application, packet_count, timeout, interface="lo0"):
        self.algorithm = algorithm
        self.application = application
        self.packet_count = packet_count
        self.timeout = timeout
        self.interface = interface

        # Initialize helpers
        self.packet_analyzer = PacketAnalyzer()
        self.simulator = TrafficSimulator()
        self.ai_model = AIModel()

    def run_benchmark(self):
        # Start time and resource tracking
        tracemalloc.start()
        start_time = time.time()
        process = psutil.Process()
        start_cpu = process.cpu_percent(interval=None)
        start_mem = process.memory_info().vms / (1024 * 1024)  # in MB

        # Simulate traffic
        self.simulator.simulate(self.application)

        # Capture packets and apply PQC
        packet_stats = self.packet_analyzer.capture_packets(
            self.algorithm, self.application,
            self.packet_count, self.timeout, self.interface
        )

        end_time = time.time()
        end_cpu = process.cpu_percent(interval=None)
        end_mem = process.memory_info().vms / (1024 * 1024)  # in MB
        tracemalloc.stop()

        # Calculate performance metrics
        execution_time = end_time - start_time
        performance_data = {
            "algorithm": self.algorithm,
            "application": self.application,
            "execution_time": execution_time,
            "cpu_usage": abs(end_cpu - start_cpu),
            "memory_usage": abs(end_mem - start_mem),
            "power_usage": 0,  # Placeholder if not available
            "packet_loss": packet_stats.get("packet_loss", 0),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        # Predict optimal algorithm (optional logic)
        try:
            features = self.ai_model.extract_features_from_test(performance_data)
            recommended_algorithm = self.ai_model.predict_optimal_algorithm(features)
            performance_data["recommended"] = recommended_algorithm
        except Exception:
            performance_data["recommended"] = "N/A"

        # Store to DB
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO pqc_benchmarks (
                algorithm, application, execution_time,
                cpu_usage, memory_usage, power_usage,
                packet_loss, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            self.algorithm, self.application,
            performance_data["execution_time"],
            performance_data["cpu_usage"],
            performance_data["memory_usage"],
            performance_data["power_usage"],
            performance_data["packet_loss"],
            performance_data["timestamp"]
        ))
        conn.commit()
        conn.close()

        return performance_data