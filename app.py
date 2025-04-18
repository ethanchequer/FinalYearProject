"""
app.py

This module initializes and runs the Flask web application. It defines API endpoints for benchmarking PQC algorithms,
retrieving the report page, and visualizing performance data. It also integrates an AI model to recommend optimal
algorithms and manages background benchmarking using multithreading.
"""

# Monkey-patch standard library for async IO with Eventlet (required by Flask-SocketIO)
import eventlet

eventlet.monkey_patch()
# Import Flask to set up the web app
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO  # adds real-time WebSocket support to Flask
# Import internal modules
from database.db_manager import get_db_connection, initialize_database, extract_features_from_db
from ai.model import AIModel
from benchmark.benchmark_manager import BenchmarkManager
from visualizations.visualizations import VisualizationManager
# pandas is used to read SQL query results into DataFrames and pass data to templates for visualization and AI analysis
import pandas as pd
# threading allows for benchmarking tasks to run in the background
import threading
from threading import Thread

app = Flask(__name__)  # Initialize the Flask web application
socketio = SocketIO(app)  # Enable WebSocket support using Flask-SocketIO

model = AIModel()  # Load the optimal algorithm AI model

# List of supported application types for traffic simulation
APPLICATION_TYPES = ["Video Streaming", "File Transfer", "VoIP", "Web Browsing"]
# Maps shortened SPHINCS+ algorithm name to the oqs internal identifier
ALGORITHM_MAP = {
    "SPHINCS+-128s": "SPHINCS+-SHA2-128s-simple",
}


""" 
User Interface Pages
These routes render web pages for users: the home page and the report page.
"""

# API route for Home Page (index.html)
@app.route('/')
def home():
    return render_template("index.html", applications=APPLICATION_TYPES)


# API route to generate the Report Page (shows test results)
@app.route('/report')
def generate_report():
    conn = get_db_connection()
    # Query benchmark results
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
    # Query average, min, and max latency per algorithm and application
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
    # Query packet loss stats and compute packet loss rate
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
    # Query average throughput in kbps
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

    # Try fetching the most recent AI recommendation from the benchmarks table
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

    # Render the report template and pass all the gathered data to it
    return render_template(
        "report.html",
        data=df.to_dict(orient="records"), # Main benchmark results
        titles=df.columns.values, # Column headers for table
        latency_data=latency_df.to_dict(orient="records"), # Latency stats
        packet_loss_data=loss_df.to_dict(orient="records"), # Packet loss stats
        throughput_data=throughput_df.to_dict(orient="records"), # Throughput stats
        recommendation=recommendation # AI-generated optimal algorithm
    )


""" 
Benchmarking: Running Tests
These endpoints trigger benchmarking processes for PQC algorithms and applications.
"""

# API endpoint that starts a benchmark test based on JSON parameters in POST request
@app.route('/benchmark', methods=['POST'])
def benchmark():
    data = request.json # Retrieve JSON data sent in the POST request
    algorithm = ALGORITHM_MAP.get(data.get("algorithm"), data.get("algorithm"))
    # Extract application type and other optional test parameters
    application = data.get("application")
    packet_count = data.get("packet_count", 50) # Default to 50 packets if not specified
    timeout = data.get("timeout", 30) # Default timeout is 30 seconds
    interface = data.get("interface", "lo0") # Use eth0 interface by default

    # Ensures both algorithm and application are provided
    if not algorithm or not application:
        return jsonify({"error": "Algorithm or application not selected"}), 400

    # Initializes and runs the benchmark test
    def run_benchmark():
        manager = BenchmarkManager(algorithm, application, packet_count, timeout, interface)
        manager.run_benchmark()

    # Run the benchmark in a separate thread to keep the server responsive
    thread = threading.Thread(target=run_benchmark)
    thread.start()

    return jsonify({"status": "started"}) # returns test successfully started


# API endpoint to run all application benchmarks for a specific algorithm ---> REMOVE ???
@app.route('/run_tests/<algorithm>', methods=['POST'])
def run_algorithm_tests(algorithm):
    if algorithm == "SPHINCS+-128s":
        algorithm = "SPHINCS+-SHA2-128s-simple"

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
            socketio.emit('test_progress',
                          {'progress': int((completed / total) * 100), 'current_test': f"{algorithm} - {app}"})
            from benchmark.benchmark_manager import BenchmarkManager
            manager = BenchmarkManager(algorithm, app, packet_map[app], timeout_map[app], "lo0")
            manager.run_benchmark()
            completed += 1
            socketio.emit('test_progress',
                          {'progress': int((completed / total) * 100), 'current_test': f"{algorithm} - {app}"})

        print(f"[DEBUG] Finished all tests for {algorithm}")

    Thread(target=run_tests).start()
    return '', 204


# API route that benchmarks all supported algorithms for a single application
@app.route('/run_all_algorithms_for_application', methods=['POST'])
def run_all_algorithms_for_application():
    from threading import Thread
    application = request.json.get("application", None) # extract the application type from the JSON request payload
    # If no application is specified in the request, return an error
    if not application:
        return jsonify({"error": "Application not specified"}), 400

    from benchmark.benchmark_manager import BenchmarkManager # Import benchmark manager for running tests
    # Function to run benchmarks for all algorithms in the background
    def run_all_for_application():
        algorithms = ["Kyber512", "Dilithium2", "SPHINCS+-SHA2-128s-simple"] # Supported PQC algorithms
        packet_count = 50  # Default number of packets to simulate
        timeout = 30  # Default timeout is 30 seconds for each benchmark
        interface = "lo0"  # Use eth0 interface by default
        results = []  # Store results to determine the most optimal algorithm later

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
                features = extract_features_from_db(latest_test)  # Prepare feature data for AI model
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
    # Run the benchmarking and prediction process in a separate thread to avoid blocking
    Thread(target=run_all_for_application).start()
    return jsonify({"message": f"Running all algorithms for the selected application: {application}"}), 200


""" 
Results Retrieval for UI
These endpoints provide benchmark and visualization data to the frontend (graphs, tables, metric results).
"""

# API route to provide visualization data for all graphs on the report page
@app.route('/get_visualization_data')
def get_visualization_data():
    conn = get_db_connection()
    # Fetch benchmarking results
    df = pd.read_sql_query("""
        SELECT algorithm, application, execution_time, cpu_usage, memory_usage, power_usage, timestamp
        FROM pqc_benchmarks
        ORDER BY timestamp DESC
    """, conn)

    # Create instance of the visualization manager, which handles data formatting for charts
    visualizer = VisualizationManager()
    # Generate default visualizations using helper methods
    visualizations = {
        "combined_execution": visualizer.generate_execution_bar_data(df),  # Combined execution time bar chart
        "resource_usage_radar": visualizer.generate_radar_chart_data(df, conn, metric_type="resource"), # CPU/memory/power radar
        "performance_metrics_radar": visualizer.generate_radar_chart_data(df, conn, metric_type="performance")  # Execution/throughput/loss radar
    }

    # Define all algorithms and applications for latency line graphs
    algorithms = ['Kyber512', 'Dilithium2', 'SPHINCS+-SHA2-128s-simple']
    applications = ['Web Browsing', 'VoIP', 'Video Streaming', 'File Transfer']

    # Loop through each algorithm to generate latency-over-time graphs
    for alg in algorithms:
        chart_id = f"{alg}_latency_over_time"  # Chart key for frontend rendering
        visualizations[chart_id] = {
            "labels": [],  # Will represent packet numbers (1, 2, ..., N)
            "datasets": []  # One dataset per application type
        }

        # Query and structure latency results for each application
        for app in applications:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT encryption_time_ms
                FROM packet_latency
                WHERE algorithm = ? AND application = ?
                ORDER BY id ASC
                LIMIT 100
            """, (alg, app))
            results = cursor.fetchall()

            # Extract latency times and assign sequential packet indices
            latencies = [row[0] for row in results]  # Latency time
            labels = list(range(1, len(latencies) + 1))  # Packet index
            # Only set labels once per graph
            if not visualizations[chart_id]["labels"]:
                visualizations[chart_id]["labels"] = labels

            # Append each application's latency data as a separate line
            visualizations[chart_id]["datasets"].append({
                "label": app,
                "data": latencies,
                "borderWidth": 2,
                "fill": False  # No area fill under the line
            })

    conn.close()
    return jsonify(visualizations)  # Return all chart-ready data as a JSON response


# API route to retrieve average CPU usage for each tested algorithm
@app.route('/cpu_usage')
def get_cpu_usage():  # Access collected CPU usage data
    conn = get_db_connection()
    # Query average CPU usage grouped by algorithm from the benchmarking table
    df = pd.read_sql_query("""
        SELECT algorithm, 
               AVG(cpu_usage) AS avg_cpu_usage
        FROM pqc_benchmarks
        GROUP BY algorithm
    """, conn)
    conn.close()
    return jsonify(df.to_dict(orient="records"))  # Convert the result to a list of dictionaries and return as JSON


# API route to retrieve average memory usage and power usage for each tested algorithm
@app.route('/memory_usage')
def get_memory_usage():
    conn = get_db_connection()
    # Query average memory usage and power usage, grouped by algorithm
    # Handles cases where power usage is missing or marked as "Not Available"
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
    return jsonify(df.to_dict(orient="records"))  # Return the results as a JSON object


# API route that returns a JSON object mapping each tested algorithm to its NIST-defined security level
@app.route('/security_levels_tested')
def get_security_levels_tested():
    conn = get_db_connection()
    # Query all distinct algorithms from benchmark results
    df = pd.read_sql_query("SELECT DISTINCT algorithm FROM pqc_benchmarks", conn)
    conn.close()
    # Extract list of tested algorithms from the DataFrame
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


# API route that retrieves or calculates the recommended optimal PQC algorithm based on test results
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


""" 
Utility / Maintenance
Route for optionally resetting the database when running new tests.
"""
# API endpoint to reset the database by clearing all result tables
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


# Run Flask App
if __name__ == '__main__':
    initialize_database()
    socketio.run(app, host="0.0.0.0", port=8000)  # If this script is run directly, start the Flask app
