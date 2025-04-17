# app.py handles benchmarking and web routes
import eventlet
eventlet.monkey_patch()
from flask import Flask, request, jsonify, render_template # imports Flask and sets up the app
from flask_socketio import SocketIO
from database.db_manager import get_db_connection, initialize_database, extract_features_from_db
import pandas as pd
import threading
from ai.model import AIModel
from benchmark.benchmark_manager import BenchmarkManager
from visualizations.visualizations import VisualizationManager

app = Flask(__name__)
socketio = SocketIO(app)

model = AIModel()

APPLICATION_TYPES = ["Video Streaming", "File Transfer", "VoIP", "Web Browsing"] # Available application types for testing
ALGORITHM_MAP = {
    "SPHINCS+-128s": "SPHINCS+-SHA2-128s-simple",
}

@app.route('/') # # Route for Home Page (index.html)
def home():
    return render_template("index.html", applications=APPLICATION_TYPES) # Pass available application types to the UI

@app.route('/benchmark', methods=['POST']) # Creates a /benchmark API route that accepts POST requests
def benchmark():
    data = request.json
    algorithm = ALGORITHM_MAP.get(data.get("algorithm"), data.get("algorithm"))
    application = data.get("application")
    packet_count = data.get("packet_count", 50)
    timeout = data.get("timeout", 30)
    interface = data.get("interface", "lo0")

    if not algorithm or not application:
        return jsonify({"error": "Algorithm or application not selected"}), 400


    def run_benchmark():
        manager = BenchmarkManager(algorithm, application, packet_count, timeout, interface)
        manager.run_benchmark()

    thread = threading.Thread(target=run_benchmark)
    thread.start()

    return jsonify({"status": "started"})

@app.route('/run_tests/<algorithm>', methods=['POST'])
def run_algorithm_tests(algorithm):
    if algorithm == "SPHINCS+-128s":
        algorithm = "SPHINCS+-SHA2-128s-simple"
    from threading import Thread

    def run_tests():
        applications = ["Video Streaming", "File Transfer", "VoIP", "Web Browsing"]
        timeout_map = {
            "Video Streaming": 60,
            "File Transfer": 60,
            "VoIP": 30,
            "Web Browsing": 60
        }
        packet_map = {
            "Video Streaming": 25,
            "File Transfer": 25,
            "VoIP": 25,
            "Web Browsing": 100
        }
        total = len(applications)
        completed = 0

        for app in applications:
            print(f"[NEW TEST] Starting test for {algorithm} - {app}")
            socketio.emit('test_progress', {'progress': int((completed / total) * 100), 'current_test': f"{algorithm} - {app}"})
            from benchmark.benchmark_manager import BenchmarkManager
            manager = BenchmarkManager(algorithm, app, packet_map[app], timeout_map[app], "lo0")
            manager.run_benchmark()
            completed += 1
            socketio.emit('test_progress', {'progress': int((completed / total) * 100), 'current_test': f"{algorithm} - {app}"})

        print(f"[DEBUG] Finished all tests for {algorithm}")

    Thread(target=run_tests).start()
    return '', 204

@app.route('/reset_database', methods=['POST'])
def reset_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Clear all known result tables
    cursor.execute("DELETE FROM pqc_benchmarks")
    cursor.execute("DELETE FROM encrypted_traffic")
    cursor.execute("DELETE FROM packet_stats")
    cursor.execute("DELETE FROM packet_latency")
    cursor.execute("DELETE FROM packet_loss_stats")

    conn.commit()
    conn.close()
    return jsonify({'message': 'Database cleared successfully.'})

@app.route('/report') # Defines the Report Page route (Shows Test Results)
def generate_report():
    conn = get_db_connection()
    df = pd.read_sql_query("""
        SELECT 
            CASE 
                WHEN algorithm LIKE 'SPHINCS+%' THEN 'SPHINCS+-128s'
                ELSE algorithm 
            END AS algorithm,
            application,
            execution_time,
            cpu_usage,
            memory_usage,
            power_usage,
            timestamp
        FROM pqc_benchmarks
        ORDER BY timestamp DESC
    """, conn)
    latency_df = pd.read_sql_query("""
        SELECT 
            CASE 
                WHEN algorithm LIKE 'SPHINCS+%' THEN 'SPHINCS+-128s'
                ELSE algorithm 
            END AS algorithm,
            application,
            AVG(encryption_time_ms) AS avg_latency,
            MIN(encryption_time_ms) AS min_latency,
            MAX(encryption_time_ms) AS max_latency
        FROM packet_latency
        GROUP BY algorithm, application
    """, conn)

    loss_df = pd.read_sql_query("""
              SELECT 
          CASE 
              WHEN algorithm LIKE 'SPHINCS+%' THEN 'SPHINCS+-128s'
              ELSE algorithm 
          END AS algorithm,
          application,
          AVG(packets_sent) AS packets_sent,
          AVG(packets_received) AS packets_successful,
          ROUND(AVG(packets_sent) - AVG(packets_received), 2) AS packets_failed,
          CASE 
              WHEN AVG(packets_sent) > 0 
              THEN ROUND((1 - (AVG(packets_received) / AVG(packets_sent))), 2)
              ELSE 0 
          END AS packet_loss_rate
      FROM packet_loss_stats
      GROUP BY algorithm, application
  """, conn)

    throughput_df = pd.read_sql_query("""
          SELECT 
              CASE 
                  WHEN algorithm LIKE 'SPHINCS+%' THEN 'SPHINCS+-128s'
                  ELSE algorithm 
              END AS algorithm,
              application,
              AVG(throughput_kbps) AS avg_throughput_kbps
          FROM throughput_stats
          GROUP BY algorithm, application
      """, conn)
    conn.close()

    recommendation = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT optimal_algorithm FROM pqc_benchmarks ORDER BY timestamp DESC LIMIT 1")
        result = cursor.fetchone()
        if result and result[0]:
            recommendation = result[0]
        else:
            recommendation = "No recommendation yet"
        conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to fetch AI recommendation: {e}")
        recommendation = "No recommendation yet"

    return render_template(
        "report.html",
        data=df.to_dict(orient="records"),
        titles=df.columns.values,
        latency_data=latency_df.to_dict(orient="records"),
        packet_loss_data=loss_df.to_dict(orient="records"),
        throughput_data=throughput_df.to_dict(orient="records"),
        recommendation=recommendation
    )

@app.route('/security_levels_tested')
def get_security_levels_tested():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT DISTINCT algorithm FROM pqc_benchmarks", conn)
    conn.close()
    tested_algorithms = df["algorithm"].tolist()
    # NIST Security Levels Dictionary
    security_levels = {
        "Kyber512": 1, "Kyber768": 3, "Kyber1024": 5,
        "Dilithium2": 2, "Dilithium3": 3, "Dilithium5": 5,
        "Falcon-512": 1, "Falcon-1024": 5,
        "SPHINCS+-SHA2-128s": 1, "SPHINCS+-SHA2-128f": 1,
        "SPHINCS+-SHA2-192s": 3, "SPHINCS+-SHA2-192f": 3,
        "SPHINCS+-SHA2-256s": 5, "SPHINCS+-SHA2-256f": 5
    }
    return jsonify({alg: security_levels.get(alg, "Unknown") for alg in tested_algorithms})

@app.route('/get_recommendation', methods=['GET'])
def get_recommendation():
    try:
        # First, check if a previously calculated recommendation exists in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT optimal_algorithm FROM pqc_benchmarks ORDER BY timestamp DESC LIMIT 1")
        result = cursor.fetchone()
        conn.close()

        if result and result[0]:
            recommendation = result[0]
            print(f"[INFO] Retrieved recommendation from database: {recommendation}")
            return jsonify({"recommendation": f"Recommended algorithm: {recommendation}"})

        # If no previous recommendation exists, calculate it
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pqc_benchmarks ORDER BY timestamp DESC LIMIT 3")
        latest_tests = cursor.fetchall()
        conn.close()

        if not latest_tests:
            return jsonify({"recommendation": "No test results available."})

        # Extract features from the last three tests (one per algorithm)
        all_predictions = []
        for test in latest_tests:
            features = extract_features_from_db(test)
            try:
                prediction = model.predict_optimal_algorithm([features])[0]
                all_predictions.append(prediction)
            except Exception as e:
                return jsonify({"error": str(e)})

        # Determine the most frequently recommended algorithm
        if all_predictions:
            from collections import Counter
            recommendation = Counter(all_predictions).most_common(1)[0][0]
            print(f"[INFO] Calculated new recommendation: {recommendation}")

            # Store the recommendation in the database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE pqc_benchmarks 
                SET optimal_algorithm = ? 
                WHERE id = (SELECT MAX(id) FROM pqc_benchmarks)
            """, (recommendation,))
            conn.commit()
            conn.close()

            return jsonify({"recommendation": f"Recommended algorithm: {recommendation}"})
        else:
            return jsonify({"recommendation": "No recommendation could be made."})

    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/run_all_algorithms_for_application', methods=['POST'])
def run_all_algorithms_for_application():
    from threading import Thread
    application = request.json.get("application", None)

    if not application:
        return jsonify({"error": "Application not specified"}), 400

    from benchmark.benchmark_manager import BenchmarkManager
    def run_all_for_application():
        algorithms = ["Kyber512", "Dilithium2", "SPHINCS+-SHA2-128s-simple"]
        packet_count = 50
        timeout = 30
        interface = "lo0"
        results = []

        for algo in algorithms:
            print(f"[NEW TEST] Starting test for {algo} - {application}")
            manager = BenchmarkManager(algo, application, packet_count, timeout, interface)
            manager.run_benchmark()

            # Get the latest test result from the database and print it
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM pqc_benchmarks ORDER BY timestamp DESC LIMIT 1")
            latest_test = cursor.fetchone()
            conn.close()

            if latest_test:
                print(f"[REPORT] Latest test result for {algo} - {application}: {latest_test}")
                features = extract_features_from_db(latest_test)
                try:
                    prediction = model.predict_optimal_algorithm([features])[0]
                    print(f"[INFO] Predicted optimal algorithm for {algo} - {application}: {prediction}")
                    results.append((algo, prediction))
                except Exception as e:
                    print(f"[ERROR] Model prediction failed for {algo} - {application}: {e}")
                    results.append((algo, "Prediction Error"))

        # Determine the best algorithm based on predictions
        best_algorithm = max(results, key=lambda x: x[1] if x[1] != "Prediction Error" else 0)[0]
        print(f"[INFO] Best algorithm for {application}: {best_algorithm}")

        # Store the recommended algorithm in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE pqc_benchmarks 
            SET optimal_algorithm = ? 
            WHERE id = (SELECT MAX(id) FROM pqc_benchmarks WHERE application = ?)
        """, (best_algorithm, application))
        conn.commit()
        conn.close()

        print("[FINAL] Tests and recommendations have been successfully generated.")

    Thread(target=run_all_for_application).start()
    return jsonify({"message": f"Running all algorithms for the selected application: {application}"}), 200

@app.route('/get_visualization_data')
def get_visualization_data():
    conn = get_db_connection()
    df = pd.read_sql_query("""
        SELECT algorithm, application, execution_time, cpu_usage, memory_usage, power_usage, timestamp
        FROM pqc_benchmarks
        ORDER BY timestamp DESC
    """, conn)

    visualizer = VisualizationManager()

    visualizations = {
        "combined_execution": visualizer.generate_execution_bar_data(df),
        "resource_usage_radar": visualizer.generate_radar_chart_data(df, conn, metric_type="resource"),
        "performance_metrics_radar": visualizer.generate_radar_chart_data(df, conn, metric_type="performance")
    }

    conn.close()
    return jsonify(visualizations)

@app.route('/cpu_usage')
def get_cpu_usage(): # Access collected CPU usage data
    conn = get_db_connection()
    df = pd.read_sql_query("""
        SELECT algorithm, 
               AVG(cpu_usage) AS avg_cpu_usage
        FROM pqc_benchmarks
        GROUP BY algorithm
    """, conn)
    conn.close()
    return jsonify(df.to_dict(orient="records"))

@app.route('/memory_usage')
def get_memory_usage(): # Access collected memory usage data
    conn = get_db_connection()
    df = pd.read_sql_query("""
        SELECT algorithm, 
               AVG(memory_usage) AS avg_memory_usage, 
               CASE 
                   WHEN LOWER(power_usage) = 'not available' OR power_usage IS NULL 
                   THEN 'Not Available'
                   ELSE power_usage
               END AS power_usage
        FROM pqc_benchmarks
        GROUP BY algorithm
    """, conn)
    conn.close()
    return jsonify(df.to_dict(orient="records"))


# Run Flask App
if __name__ == '__main__':
    initialize_database()
    socketio.run(app, host="0.0.0.0", port=8000) # If this script is run directly, start the Flask app
