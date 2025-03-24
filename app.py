# app.py handles benchmarking and web routes
# This version of the app runs the execution time, CPU, memory and power usage for the PQC benchmarks.
from flask import Flask, request, jsonify, render_template, redirect, url_for # imports Flask and sets up the app
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
import tracemalloc
from scapy.all import sniff, Raw

app = Flask(__name__)
socketio = SocketIO(app)

NUM_TRIALS = 10 # Define the number of trials per test to improve accuracy
APPLICATION_TYPES = ["Video Streaming", "File Transfer", "VoIP", "Web Browsing"] # Available application types for testing

#############
# DATABASES #
#############

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

    # Table for storing packet stats
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packet_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            algorithm TEXT,
            application TEXT,
            original_size INTEGER,
            encrypted_size INTEGER,
            encryption_time_ms REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table for storing per-packet encryption latency
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packet_latency (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            algorithm TEXT,
            application TEXT,
            encryption_time_ms REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

######################
# TRAFFIC SIMULATION #
######################

# Simulating real application traffic for PQC
def simulate_application_traffic(application):
    """Simulates traffic generation for a specific application type using subprocess."""
    try:
        if application == "Video Streaming":
            # Stream a local video file over UDP to localhost
            return subprocess.Popen([
                "ffmpeg", "-re", "-i", "sample_video.mp4",
                "-f", "mpegts", "udp://127.0.0.1:1234"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif application == "File Transfer":
            # Start a simple HTTP server to simulate file download
            return subprocess.Popen(["python3", "-m", "http.server", "8080"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif application == "Web Browsing":
            # Simulate HTTP GET requests to localhost server
            return subprocess.Popen([
                "bash", "-c",
                "for i in {1..10}; do curl -s http://127.0.0.1:8080 > /dev/null; sleep 0.5; done"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif application == "VoIP":
            # Send periodic UDP packets to simulate voice packets
            return subprocess.Popen([
                "bash", "-c",
                "for i in {1..50}; do echo 'voice' | nc -u -w1 127.0.0.1 5678; sleep 0.2; done"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    except Exception as e:
        print(f"Simulation error: {e}")
        return None

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

# Capture live network packets using scapy
def capture_packets_with_scapy(algorithm, application, public_key, packet_count, timeout, interface):
    """Capture live packets with Scapy and apply PQC encryption on payloads."""
    def process_packet(packet):
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            start = time.perf_counter()
            encrypted_data = apply_pqc_algorithm(algorithm, payload, public_key)
            enc_time = (time.perf_counter() - start) * 1000  # ms
            if encrypted_data:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO encrypted_traffic (algorithm, application, original_size, encrypted_size)
                    VALUES (?, ?, ?, ?)
                """, (algorithm, application, len(payload), len(encrypted_data)))

                cursor.execute("""
                    INSERT INTO packet_stats (algorithm, application, original_size, encrypted_size, encryption_time_ms)
                    VALUES (?, ?, ?, ?, ?)
                """, (algorithm, application, len(payload), len(encrypted_data), enc_time))

                cursor.execute("""
                    INSERT INTO packet_latency (algorithm, application, encryption_time_ms)
                    VALUES (?, ?, ?)
                """, (algorithm, application, enc_time))
                conn.commit()
                conn.close()

    sniff(prn=process_packet, count=packet_count, store=False, timeout=timeout, iface=interface)

################
# BENCHMARKING #
################

def benchmark_pqc(algorithm, application, packet_count=50, timeout=30, interface="lo0"):
    """Runs the full benchmark process with real-time traffic encryption and refined memory tracking."""
    gc.collect()
    tracemalloc.start()
    process = psutil.Process()
    start_time = time.perf_counter()
    start_cpu = process.cpu_percent(interval=None)
    start_mem = process.memory_info().rss / (1024 * 1024)  # MB

    # Generate keys once at the start
    if algorithm == "Kyber512":
        kem = oqs.KeyEncapsulation("Kyber512")
        public_key = kem.generate_keypair()
    elif algorithm in ["Dilithium2", "SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHAKE-128s-simple"]:
        sig = oqs.Signature(algorithm)
        public_key = sig.generate_keypair()
    else:
        public_key = None

    traffic_process = simulate_application_traffic(application)
    capture_packets_with_scapy(algorithm, application, public_key, packet_count, timeout, interface)

    if traffic_process:
        traffic_process.terminate()

    # After capturing packets and terminating simulation
    end_time = time.perf_counter()
    end_cpu = process.cpu_percent(interval=None)
    end_mem = process.memory_info().rss / (1024 * 1024)  # MB
    tracemalloc.stop()

    # Calculate performance metrics
    execution_time = (end_time - start_time)  # in seconds
    cpu_usage = abs(end_cpu - start_cpu)  # %
    memory_usage = abs(end_mem - start_mem)  # MB

    # Store benchmark results in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO pqc_benchmarks (algorithm, application, execution_time, cpu_usage, memory_usage, power_usage)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        algorithm, application,
        execution_time,
        cpu_usage,
        memory_usage,
        "Not Available"
    ))
    conn.commit()
    conn.close()

    return {
        "avg_execution_time_ms": execution_time,
        "avg_cpu_usage": cpu_usage,
        "avg_memory_usage_mb": memory_usage,
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
    packet_count = data.get("packet_count", 50)
    timeout = data.get("timeout", 30)
    interface = data.get("interface", "lo0")

    if not algorithm or not application:
        return jsonify({"error": "Algorithm or application not selected"}), 400

    thread = threading.Thread(target=benchmark_pqc, args=(algorithm, application, packet_count, timeout, interface))
    thread.start()

    return jsonify({"status": "started"})


# Report Page (Shows Test Results)
@app.route('/report') # Defines the /report page route
def generate_report():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM pqc_benchmarks ORDER BY timestamp DESC", conn)
    latency_df = pd.read_sql_query("""
        SELECT algorithm, application, AVG(encryption_time_ms) AS avg_latency,
               MIN(encryption_time_ms) AS min_latency,
               MAX(encryption_time_ms) AS max_latency
        FROM packet_latency
        GROUP BY algorithm, application
    """, conn)
    conn.close()

    return render_template(
        "report.html",
        data=df.to_dict(orient="records"),
        titles=df.columns.values,
        latency_data=latency_df.to_dict(orient="records")
    )


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


@app.route('/latency_stats')
def get_latency_stats():
    conn = get_db_connection()
    df = pd.read_sql_query("""
        SELECT algorithm, application, AVG(encryption_time_ms) AS avg_latency,
               MIN(encryption_time_ms) AS min_latency,
               MAX(encryption_time_ms) AS max_latency
        FROM packet_latency
        GROUP BY algorithm, application
    """, conn)
    conn.close()
    return jsonify(df.to_dict(orient="records"))

# Initialize Database Before Running
initialize_database()


# Run Flask App
if __name__ == '__main__': # If this script is run directly, start the Flask app
    app.run(host="192.168.68.155", port=5000, debug=True, threaded=True) # Enable debug mode for:
                        # Automatic reloading on code changes.
                        # Error traceback in the browser when exceptions occur
