"""
visualizations.py

This module contains the VisualizationManager class, responsible for generating performance and resource usage plots.
It supports plotting throughput and latency comparisons, generating radar charts, and preparing bar chart datasets for
frontend visualization.
"""

import matplotlib.pyplot as plt  # Used for creating graphs
import pandas as pd  # Used for data manipulation and analysis
import os  # Used for handling file paths

# The VisualizationManager class provides methods to generate visual representations of test results data
class VisualizationManager:
    # Initialize the manager with folders for data input and output plot images
    def __init__(self, data_folder="data", output_folder="static/plots"):
        self.data_folder = data_folder
        self.output_folder = output_folder
        os.makedirs(self.output_folder, exist_ok=True)

    # Load CSV data file from the data folder
    def load_data(self, filename):
        path = os.path.join(self.data_folder, filename)
        return pd.read_csv(path)

    # Generate a line plot comparing throughput (kbps) across algorithms and applications
    def generate_throughput_plot(self, df, output_filename="throughput_plot.png"):
        plt.figure()
        for app in df["application"].unique():
            subset = df[df["application"] == app]
            # Plot throughput values for each application
            plt.plot(subset["algorithm"], subset["throughput_kbps"], marker="o", label=app)

        plt.title("Throughput Comparison")
        plt.xlabel("Algorithm")
        plt.ylabel("Throughput (kbps)")
        plt.legend()
        output_path = os.path.join(self.output_folder, output_filename)
        plt.savefig(output_path)
        plt.close()
        return output_path

    # Generate a line plot comparing latency (ms) across algorithms and applications
    def generate_latency_plot(self, df, output_filename="latency_plot.png"):
        plt.figure()
        for app in df["application"].unique():
            subset = df[df["application"] == app]
            plt.plot(subset["algorithm"], subset["avg_latency_ms"], marker="o", label=app)

        plt.title("Latency Comparison")
        plt.xlabel("Algorithm")
        plt.ylabel("Latency (ms)")
        plt.legend()
        output_path = os.path.join(self.output_folder, output_filename)
        plt.savefig(output_path)
        plt.close()
        return output_path

    # Normalize a value to a percentage of the given max value (for consistent radar chart scaling)
    def normalize(self, value, max_value):
        return (value / max_value) * 100 if max_value else 0

    # Generate radar chart data (resource or performance metrics) for all algorithms
    def generate_radar_chart_data(self, df, conn, metric_type="resource"):
        resource_metrics = {
            "cpu_usage": 100,
            "memory_usage": 20,
            "power_usage": 20
        }
        performance_metrics = {
            "latency": 1000,
            "throughput": 1000,
            "execution_time": 30,
            "packet_loss": 100
        }

        radar_data = {
            "labels": [],
            "datasets": []
        }

        if metric_type == "resource":
            radar_data["labels"] = ["CPU Usage (%)", "Memory Usage (MB)", "Power Usage (W)"]
            # Calculate and normalize average CPU, memory, and power usage per algorithm
            algorithms = df["algorithm"].unique().tolist()
            for alg in algorithms:
                alg_df = df[df["algorithm"] == alg]
                avg_cpu = self.normalize(alg_df["cpu_usage"].mean(), resource_metrics["cpu_usage"])
                avg_memory = self.normalize(alg_df["memory_usage"].mean(), resource_metrics["memory_usage"])
                avg_power = self.normalize(pd.to_numeric(alg_df["power_usage"].replace("Not Available", 0), errors='coerce').mean(), resource_metrics["power_usage"])

                radar_data["datasets"].append({
                    "label": alg,
                    "data": [avg_cpu, avg_memory, avg_power]
                })
        else:
            radar_data["labels"] = ["Latency (ms)", "Throughput (kbps)", "Execution Time (s)", "Packet Loss (%)"]
            # Query the database for average performance metrics per algorithm and normalize
            algorithms = df["algorithm"].unique().tolist()
            for alg in algorithms:
                alg_df = df[df["algorithm"] == alg]
                latency_query = pd.read_sql_query("SELECT AVG(encryption_time_ms) FROM packet_latency WHERE algorithm = ?", conn, params=[alg])
                avg_latency = self.normalize(latency_query.iloc[0, 0] or 0, performance_metrics["latency"])
                throughput_query = pd.read_sql_query("SELECT AVG(throughput_kbps) FROM throughput_stats WHERE algorithm = ?", conn, params=[alg])
                avg_throughput = self.normalize(throughput_query.iloc[0, 0] or 0, performance_metrics["throughput"])
                avg_execution_time = self.normalize(alg_df["execution_time"].mean(), performance_metrics["execution_time"])
                packet_loss_query = pd.read_sql_query("SELECT AVG(packet_loss_rate) FROM packet_loss_stats WHERE algorithm = ?", conn, params=[alg])
                avg_packet_loss = self.normalize(packet_loss_query.iloc[0, 0] or 0, performance_metrics["packet_loss"])

                radar_data["datasets"].append({
                    "label": alg,
                    "data": [avg_latency, avg_throughput, avg_execution_time, avg_packet_loss]
                })

        return radar_data

    # Prepare execution time data in bar chart format grouped by application and algorithm
    def generate_execution_bar_data(self, df):
        numeric_columns = df.select_dtypes(include=["number"]).columns
        combined_df = df.groupby(["application", "algorithm"])[numeric_columns].mean().reset_index()
        applications = combined_df["application"].unique()
        colors = {
            "SPHINCS+-SHA2-128s-simple": "rgba(54, 162, 235, 0.6)",
            "Dilithium2": "rgba(255, 99, 132, 0.6)",
            "Kyber512": "rgba(255, 205, 86, 0.6)"
        }
        datasets = []

        # Create a dataset entry for each algorithm showing average execution time per application
        for alg in combined_df["algorithm"].unique():
            data = []
            for app in applications:
                value = combined_df.loc[(combined_df["algorithm"] == alg) & (combined_df["application"] == app), "execution_time"]
                data.append(value.iloc[0] if not value.empty else 0)

            datasets.append({
                "label": alg,
                "backgroundColor": colors.get(alg, "rgba(75, 192, 192, 0.6)"),
                "data": data
            })

        return {
            "labels": list(applications),
            "datasets": datasets
        }
