# app.py handles benchmarking and web routes
# imports Flask and sets up the app
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_socketio import SocketIO, emit
import time
import oqs # Python bindings for the OQS library
import os
import sqlite3 # SQLite database
import pandas as pd
import psutil
import threading
app = Flask(__name__)
socketio = SocketIO(app)

# Different message sizes to run multiple tests
MESSAGE_SIZES = [32, 256, 1024, 40968192, 16384, 32768, 65536]  # Byte sizes to test (32B, 256B, 1KB, 4KB)

# Function to connect to the SQLite results database
def get_db_connection():
    conn = sqlite3.connect("pqc_results.db", check_same_thread=False)
    return conn # Returns the SQLite database connection

# Ensure the database and table exist
def initialize_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create table if it does not exist
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS pqc_benchmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT,
                message_size INTEGER,
                execution_time REAL,
                cpu_usage REAL,
                memory_usage REAL,
                power_usage TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
    conn.commit()
    conn.close()


# Function to fetch all benchmark results from the results database
def get_all_benchmarks():
    conn = get_db_connection() # Connect to the database
    df = pd.read_sql_query("SELECT * FROM pqc_benchmarks ORDER BY timestamp DESC, message_size ASC", conn)
    # Executes an SQL query to retrieve all records from the benchmarks table
    # sorted by timestamp in descending order (newest results first)
    # Returns the results as a pandas DataFrame
    conn.close() # Closes the database connection
    return df # Returns the DataFrame containing all benchmark results


# Benchmarking function for PQC algorithms (Runs PQC Tests)
def benchmark_pqc(algorithm):
    try:
        process = psutil.Process() # Get current process information
        results = []

        for size in MESSAGE_SIZES:
            message = bytes(size)  # Generate a message of the given size
            start_time = time.time()
            start_cpu = psutil.cpu_percent(interval=None)
            start_mem = process.memory_info().rss / (1024 * 1024)  # MB

            # Handle Kyber512 algorithm
            if algorithm == "Kyber512":
                kem = oqs.KeyEncapsulation("Kyber512")
                public_key = kem.generate_keypair()
                ciphertext, shared_secret_enc = kem.encap_secret(public_key)
                shared_secret_dec = kem.decap_secret(ciphertext)


            # Handle Dilithium2 algorithm
            elif algorithm == "Dilithium2":
                sig = oqs.Signature("Dilithium2")
                try:
                    public_key = sig.generate_keypair()  # Only public key is returned
                    print(f"✅ Keypair generated for Dilithium2")
                except Exception as e:
                    print(f"❌ Failed to generate keypair for Dilithium2: {e}")
                    return {"error": f"Failed to generate keypair for Dilithium2: {str(e)}"}
                try:
                    signature = sig.sign(message)  # No secret key needed
                    print(f"✅ Signature generated for Dilithium2")
                except Exception as e:
                    print(f"❌ Failed to sign message with Dilithium2: {e}")
                    return {"error": f"Failed to sign message with Dilithium2: {str(e)}"}
                try:
                    is_valid = sig.verify(message, signature, public_key)
                    if not is_valid:
                        print(f"❌ Signature verification failed for Dilithium2")
                        return {"error": f"Dilithium2 signature verification failed"}
                    print(f"✅ Signature verified for Dilithium2")
                except Exception as e:
                    print(f"❌ Failed to verify signature with Dilithium2: {e}")
                    return {"error": f"Failed to verify signature with Dilithium2: {str(e)}"}


            # Handle SPHINCS+-128s algorithm
            elif algorithm in ["SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHAKE-128s-simple"]:
                try:
                    sig = oqs.Signature(algorithm)
                    print(f"✅ SPHINCS+ ({algorithm}) Signature object created")
                except Exception as e:
                    print(f"❌ Failed to initialize {algorithm}: {e}")
                    return {"error": f"Failed to initialize {algorithm}: {str(e)}"}
                try:
                    public_key = sig.generate_keypair()  # Only public key is returned
                    print(f"✅ Keypair generated for {algorithm}")
                except Exception as e:
                    print(f"❌ Failed to generate keypair for {algorithm}: {e}")
                    return {"error": f"Failed to generate keypair for {algorithm}: {str(e)}"}
                try:
                    signature = sig.sign(message)  # No secret key needed
                    print(f"✅ Signature generated for {algorithm}")
                except Exception as e:
                    print(f"❌ Failed to sign message with {algorithm}: {e}")
                    return {"error": f"Failed to sign message with {algorithm}: {str(e)}"}
                try:
                    is_valid = sig.verify(message, signature, public_key)
                    if not is_valid:
                        print(f"❌ Signature verification failed for {algorithm}")
                        return {"error": f"{algorithm} signature verification failed"}
                    print(f"✅ Signature verified for {algorithm}")
                except Exception as e:
                    print(f"❌ Failed to verify signature with {algorithm}: {e}")
                    return {"error": f"Failed to verify signature with {algorithm}: {str(e)}"}

            # Measure execution time
            execution_time = time.time() - start_time

            # Measure CPU usage over a short interval
            cpu_usage = psutil.cpu_percent(interval=0.1)  # More accurate

            # Measure per-core CPU usage
            cpu_usage_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
            avg_cpu_usage = sum(cpu_usage_per_core) / len(cpu_usage_per_core)

            # Measure memory usage after execution
            end_mem = process.memory_info().rss / (1024 * 1024)

            # Measure power consumption
            power_usage = get_power_usage()

            # Store results
            results.append((size, execution_time, avg_cpu_usage, end_mem, power_usage))

        return {
            "algorithm": algorithm,
            "results": results # Store different message size results
        }

    except Exception as e:
        return {"error": str(e)}


# Read power stats from the Raspberry Pi
def get_power_usage():
    try:
        power_file = "/sys/class/power_supply/battery/voltage_now"
        if os.path.exists(power_file):
            with open(power_file, "r") as f:
                voltage = int(f.read().strip()) / 1e6  # Convert µV to V

            current_file = "/sys/class/power_supply/battery/current_now"
            if os.path.exists(current_file):
                with open(current_file, "r") as f:
                    current = int(f.read().strip()) / 1e6  # Convert µA to A

                power_usage = round(voltage * current, 2)  # Compute Power (W)
                return power_usage
        return "Not Available"
    except Exception:
        return "Error"



# Async Function to Run Benchmarks and Update Progress
def run_benchmarks(algorithms):
    conn = get_db_connection()

    for algorithm in algorithms:
        socketio.emit("progress", {"message": f"Running {algorithm}..."})
        result = benchmark_pqc(algorithm)

        if "error" not in result:
            print(f"✅ Inserting {algorithm} results into the database")

            for message_size, execution_time, cpu_usage, memory_usage, power_usage in result["results"]:
                conn.execute("""
                            INSERT INTO pqc_benchmarks (algorithm, message_size, execution_time, cpu_usage, memory_usage, power_usage)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (algorithm, message_size, execution_time, cpu_usage, memory_usage, power_usage))
                conn.commit()
        else:
            print(f"❌ Error running {algorithm}: {result['error']}")
            socketio.emit("progress", {"message": f"Error: {result['error']}"})  # Display in UI

    conn.close()

    with app.app_context():
        socketio.emit("progress", {"message": "Completed!"})
        socketio.emit("redirect", {"url": "/report"})  # Redirect to report page





# Route for Home Page (Frontend)
# Renders index.html when a user visits /
@app.route('/') # Defines the route for the home page (/)
def home():
    return render_template("index.html") # When a user visits /, renders index.html (frontend webpage)


# Route to Start Benchmarks
@app.route('/benchmark', methods=['POST']) # Creates a /benchmark API route that accepts POST requests
def benchmark():
    data = request.json
    algorithm = data.get("algorithm")

    if not algorithm:
        return jsonify({"error": "No algorithm selected"}), 400

    thread = threading.Thread(target=run_benchmarks, args=([algorithm],))
    thread.start()

    return jsonify({"status": "started"})


# Report Page (Shows Test Results)
@app.route('/report') # Defines the /report page route
def generate_report():
    df = get_all_benchmarks() # Calls get_all_benchmarks() to fetch benchmark results from the database
    return render_template("report.html", data=df.to_dict(orient="records"), titles=df.columns.values)
    # Renders report.html with the fetched benchmark results as tables and column titles
    # tables=[df.to_html()]: Converts the DataFrame to an HTML table
    # titles=df.columns.values: Passes column names for formatting


# Function to send execution time data as JSON for execution time bar chart
@app.route('/execution_times')
def get_execution_times():
    conn = get_db_connection()
    df = pd.read_sql_query(
        "SELECT algorithm, message_size, AVG(execution_time) AS avg_time FROM pqc_benchmarks GROUP BY algorithm, message_size",
        conn)
    conn.close()

    # Convert to proper JSON format for visualization
    results = {}
    for row in df.itertuples():
        if row.algorithm not in results:
            results[row.algorithm] = []
        results[row.algorithm].append({"message_size": row.message_size, "execution_time": row.avg_time})

    return jsonify(results)


# API route to return security levels for each algorithm
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
        "SPHINCS+-128s": 1, "SPHINCS+-128f": 1,
        "SPHINCS+-192s": 3, "SPHINCS+-192f": 3,
        "SPHINCS+-256s": 5, "SPHINCS+-256f": 5
    }
    return jsonify({alg: security_levels.get(alg, "Unknown") for alg in tested_algorithms})

# API route to access collected CPU and memory data
@app.route('/cpu_memory_usage')
def get_cpu_memory_usage():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT algorithm, cpu_usage, memory_usage FROM pqc_benchmarks", conn)
    conn.close()

    # Convert DataFrame to JSON format
    data = df.groupby("algorithm").mean().reset_index().to_dict(orient="records")

    return jsonify(data)

# Initialize Database Before Running
initialize_database()


# Run Flask App
if __name__ == '__main__': # If this script is run directly, start the Flask app
    app.run(host="192.168.68.155", port=5000, debug=True, threaded=True) # Enable debug mode for:
                        # Automatic reloading on code changes.
                        # Error traceback in the browser when exceptions occur

# This version of the app runs the front end and the execution time for the PQC benchmarks.
# Need to develop the back end to implement more metrics and provide more performance insight.