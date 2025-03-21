# app.py handles benchmarking and web routes
# imports Flask and sets up the app
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_socketio import SocketIO, emit
import time
import oqs # Python bindings for the OQS library
import os
import subprocess
import sqlite3 # SQLite database
import pandas as pd
import psutil
import threading
import gc

app = Flask(__name__)
socketio = SocketIO(app)

# Define the number of trials per test to improve accuracy
NUM_TRIALS = 10

# Available application types for testing
APPLICATION_TYPES = ["Video Streaming", "File Transfer", "VoIP", "Web Browsing"]

############
# DATABASE #
############

# Function to connect to the SQLite results database
def get_db_connection():
    """ Connect to the SQLite database. """
    conn = sqlite3.connect("pqc_results.db", check_same_thread=False)
    return conn # Returns the SQLite database connection

# Ensure the database and table exist
def initialize_database():
    """ Initialize the database and tables for results storage. """
    conn = get_db_connection()
    cursor = conn.cursor()
    # Check if the 'application' column exists in pqc_benchmarks
    cursor.execute("PRAGMA table_info(pqc_benchmarks)")
    columns = [column[1] for column in cursor.fetchall()]
    if "application" not in columns:
        cursor.execute("ALTER TABLE pqc_benchmarks ADD COLUMN application TEXT")

    # Table for benchmarking results
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS pqc_benchmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT,
                application TEXT,
                execution_time REAL,
                cpu_usage REAL,
                memory_usage REAL,
                power_usage TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

    # Table for storing encrypted/signed traffic payloads
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS encrypted_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT,
                application TEXT,
                original_size INTEGER,
                encrypted_size INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

    conn.commit()
    conn.close()


##########################
# PQC ENCRYPTION/SIGNING #
##########################

def apply_pqc_algorithm(algorithm, payload, public_key):
    """ Encrypts or signs a single payload using the selected PQC algorithm in real-time. """
    try:
        if algorithm == "Kyber512":
            kem = oqs.KeyEncapsulation("Kyber512")
            ciphertext, _ = kem.encap_secret(public_key)
            return ciphertext

        elif algorithm == "Dilithium2":
            sig = oqs.Signature("Dilithium2")
            signature = sig.sign(payload)
            if sig.verify(payload, signature, public_key):
                return signature

        elif algorithm in ["SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHAKE-128s-simple"]:
            sig = oqs.Signature(algorithm)
            signature = sig.sign(payload)
            if sig.verify(payload, signature, public_key):
                return signature

        return None

    except Exception as e:
        return None


################
# BENCHMARKING #
################

def benchmark_pqc(algorithm, application):
    """ Runs the full benchmark process with real-time traffic encryption. """
    process = psutil.Process()
    execution_times, cpu_usages, memory_usages = [], [], []

    # Generate keys once at the start
    if algorithm == "Kyber512":
        kem = oqs.KeyEncapsulation("Kyber512")
        public_key = kem.generate_keypair()
    elif algorithm in ["Dilithium2", "SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHAKE-128s-simple"]:
        sig = oqs.Signature(algorithm)
        public_key = sig.generate_keypair()
    else:
        public_key = None

    for _ in range(NUM_TRIALS):
        # Simulate application data
        data_chunk = {
            "File Transfer": b"File data chunk",
            "Video Streaming": b"Video frame data",
            "VoIP": b"Voice packet data",
            "Web Browsing": b"HTTP request data"
        }.get(application, b"Generic data")

        # Start performance tracking
        start_time = time.perf_counter_ns()
        start_cpu = process.cpu_percent(interval=None)
        start_mem = process.memory_info().rss / (1024 * 1024) # Before encryption in KB
        encrypted_data = apply_pqc_algorithm(algorithm, data_chunk, public_key)

        gc.collect() # Force garbage collection to prevent premature memory release

        # End performance tracking
        execution_time = (time.perf_counter_ns() - start_time) / 1_000_000 # Convert to milliseconds
        end_cpu = process.cpu_percent(interval=None)
        end_mem = process.memory_info().rss / (1024 * 1024)  # Initialize with Resident Set Size (KB)
        end_mem = max(end_mem, process.memory_info().vms / (1024 * 1024))  # Use vms if higher

        execution_times.append(execution_time)
        cpu_usages.append(abs(end_cpu - start_cpu))
        memory_usages.append(abs(end_mem - start_mem)) # Compute actual memory difference

        # Store encrypted data size
        if encrypted_data is not None:
            original_size = len(data_chunk)
            encrypted_size = len(encrypted_data)
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO encrypted_traffic (algorithm, application, original_size, encrypted_size)
                VALUES (?, ?, ?, ?)
            """, (algorithm, application, original_size, encrypted_size))
            conn.commit()
            conn.close()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO pqc_benchmarks (algorithm, application, execution_time, cpu_usage, memory_usage, power_usage)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        algorithm, application,
        round(sum(execution_times) / len(execution_times), 6),  # Store with microsecond precision
        round(sum(cpu_usages) / len(cpu_usages), 2),
        round(sum(memory_usages) / len(memory_usages) / 1024, 2),
        "Not Available"
    ))
    conn.commit()
    conn.close()

    return {
        "avg_execution_time_ms": round(sum(execution_times) / len(execution_times), 2),
        "avg_cpu_usage": round(sum(cpu_usages) / len(cpu_usages), 2),
        "avg_memory_usage_mb": round(sum(memory_usages) / len(memory_usages), 2),
    }


##########
# ROUTES #
##########

# Route for Home Page (Frontend)
# Renders index.html when a user visits /
@app.route('/') # Defines the route for the home page (/)
def home():
    return render_template("index.html", applications=APPLICATION_TYPES) # Pass available application types to the UI


# Route to Start Benchmarks
@app.route('/benchmark', methods=['POST']) # Creates a /benchmark API route that accepts POST requests
def benchmark():
    data = request.json
    algorithm = data.get("algorithm")
    application = data.get("application")

    if not algorithm or not application:
        return jsonify({"error": "Algorithm or application not selected"}), 400

    thread = threading.Thread(target=benchmark_pqc, args=(algorithm, application))
    thread.start()

    return jsonify({"status": "started"})


# Report Page (Shows Test Results)
@app.route('/report') # Defines the /report page route
def generate_report():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM pqc_benchmarks ORDER BY timestamp DESC", conn)
    conn.close()
    return render_template("report.html", data=df.to_dict(orient="records"), titles=df.columns.values)


# Function to send execution time data as JSON for execution time bar chart
@app.route('/execution_times')
def get_execution_times():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT algorithm, execution_time FROM pqc_benchmarks", conn)
    conn.close()

    # Keep execution time in seconds (remove microsecond conversion)
    avg_exec_time = df.groupby("algorithm")["execution_time"].mean().reset_index()

    return jsonify(avg_exec_time.to_dict(orient="records"))

@app.route('/execution_vs_cpu')
def get_execution_vs_cpu():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT algorithm, execution_time, cpu_usage FROM pqc_benchmarks", conn)
    conn.close()

    # Convert execution time from seconds to microseconds (µs)
    df["execution_time"] = df["execution_time"] * 1_000_000  # Convert to µs

    return jsonify(df.to_dict(orient="records"))


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
        "SPHINCS+-SHA2-128s": 1, "SPHINCS+-SHA2-128f": 1,
        "SPHINCS+-SHA2-192s": 3, "SPHINCS+-SHA2-192f": 3,
        "SPHINCS+-SHA2-256s": 5, "SPHINCS+-SHA2-256f": 5
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

# This version of the app runs the execution time, CPU, memory and power usage for the PQC benchmarks.
# Execution time is the only calculation concern...
# Next step is to include application traffic