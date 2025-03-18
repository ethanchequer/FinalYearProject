# app.py handles benchmarking and web routes
# imports Flask and sets up the app
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_socketio import SocketIO, emit
import time
import oqs # Python bindings for the OQS library
import os
import subprocess
import pyshark
import sqlite3 # SQLite database
import pandas as pd
import psutil
import threading

app = Flask(__name__)
socketio = SocketIO(app)

# Define the number of trials per test to improve accuracy
NUM_TRIALS = 10

# Available application types for testing
APPLICATION_TYPES = ["Video Streaming", "File Transfer", "VoIP", "Web Browsing"]

# Different message sizes to run multiple tests
MESSAGE_SIZES = [32, 256, 1024, 40968192, 16384, 32768, 65536]  # Byte sizes to test (32B, 256B, 1KB, 4KB)

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


###################
# TRAFFIC CAPTURE #
###################

# Traffic capture function based on application type
def capture_traffic(application, duration=10):
    """ Captures application-specific traffic using tcpdump and stops after a set duration. """
    pcap_file = f"{application.replace(' ', '_').lower()}_traffic.pcap"
    tcpdump_process = None

    try:
        if application == "Video Streaming":
            subprocess.Popen(["ffmpeg", "-i", "input.mp4", "-f", "mpegts", "udp://127.0.0.1:1234"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif application == "File Transfer":
            subprocess.Popen(["iperf3", "-s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        tcpdump_process = subprocess.Popen(["tcpdump", "-i", "wlan0", "-w", pcap_file],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        time.sleep(duration)  # Capture traffic for `duration` seconds
        if tcpdump_process:
            tcpdump_process.terminate()  # Stop tcpdump after capture time

        return pcap_file
    except Exception as e:
        return str(e)

######################
# TRAFFIC EXTRACTION #
######################

def extract_payloads(pcap_file):
    """ Extracts payload data from the captured .pcap file. """
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter="tcp or udp")
        payloads = []

        for packet in cap:
            if hasattr(packet, "tcp") and hasattr(packet.tcp, "payload"):
                payloads.append(bytes.fromhex(packet.tcp.payload.replace(":", "")))
            elif hasattr(packet, "udp") and hasattr(packet.udp, "payload"):
                payloads.append(bytes.fromhex(packet.udp.payload.replace(":", "")))

        cap.close()
        return payloads
    except Exception as e:
        return {"error": str(e)}

##########################
# PQC ENCRYPTION/SIGNING #
##########################

def apply_pqc_algorithm(algorithm, payloads):
    """ Encrypts or signs payloads using the selected PQC algorithm. """
    try:
        encrypted_payloads = []

        if algorithm == "Kyber512":
            kem = oqs.KeyEncapsulation("Kyber512")
            public_key = kem.generate_keypair()

            for payload in payloads:
                ciphertext, _ = kem.encap_secret(public_key)
                if isinstance(ciphertext, bytes):
                    encrypted_payloads.append((len(payload), len(ciphertext)))  # Ensure a tuple is returned
                else:
                    encrypted_payloads.append((len(payload), 0))  # Handle unexpected output safely

        elif algorithm == "Dilithium2":
            sig = oqs.Signature("Dilithium2")
            public_key = sig.generate_keypair()

            for payload in payloads:
                signature = sig.sign(payload)
                if sig.verify(payload, signature, public_key):
                    encrypted_payloads.append((len(payload), len(signature)))
                else:
                    encrypted_payloads.append((len(payload), 0))  # Signature failed, store safe value

        elif algorithm in ["SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHAKE-128s-simple"]:
            sig = oqs.Signature(algorithm)
            public_key = sig.generate_keypair()

            for payload in payloads:
                signature = sig.sign(payload)
                if sig.verify(payload, signature, public_key):
                    encrypted_payloads.append((len(payload), len(signature)))
                else:
                    encrypted_payloads.append((len(payload), 0))  # Handle failure case safely

        return encrypted_payloads  # Always return a list of (original_size, encrypted_size)

    except Exception as e:
        return [(0, 0)]  # Return safe fallback value to prevent crashes

###########################
# PERFORMANCE MEASUREMENT #
###########################

def measure_performance(algorithm, payloads):
    """ Measures execution time, CPU, memory, and power usage of PQC encryption/signing. """
    process = psutil.Process()
    execution_times, cpu_usages, memory_usages, power_usages = [], [], [], []

    for payload in payloads:
        start_time = time.perf_counter()
        start_cpu = psutil.cpu_percent(interval=0.1)
        start_mem = process.memory_info().rss / (1024 * 1024)  # Before encryption

        encrypted_payloads = apply_pqc_algorithm(algorithm, [payload])

        execution_time = time.perf_counter() - start_time  # Already in seconds
        mid_mem = process.memory_info().rss / (1024 * 1024)  # Immediately after encryption
        end_mem = psutil.virtual_memory().used / (1024 * 1024)  # Overall system usage
        cpu_usage = psutil.cpu_percent(interval=0.1)
        power_usage = "Not Available"  # Future implementation for power measurement

        execution_times.append(execution_time)
        cpu_usages.append(cpu_usage)
        memory_usages.append(mid_mem - start_mem)
        power_usages.append(power_usage)

    return {
        "avg_execution_time_ms": round(sum(execution_times) / len(execution_times), 2),
        "avg_cpu_usage": round(sum(cpu_usages) / len(cpu_usages), 2),
        "avg_memory_usage_mb": round(sum(memory_usages) / len(memory_usages), 2),
        "avg_power_usage_watts": round(sum([x for x in power_usages if isinstance(x, (int, float))], 2))
        if power_usages else "Not Available"
    }

################
# BENCHMARKING #
################

def benchmark_pqc(algorithm, application):
    """ Runs the full benchmark process. """
    pcap_file = capture_traffic(application)
    payloads = extract_payloads(pcap_file)

    # Encrypt and store payload size differences
    encrypted_payloads = apply_pqc_algorithm(algorithm, payloads)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Store encrypted payload sizes
    for original_size, encrypted_size in encrypted_payloads:
        cursor.execute("""
            INSERT INTO encrypted_traffic (algorithm, application, original_size, encrypted_size)
            VALUES (?, ?, ?, ?)
        """, (algorithm, application, original_size, encrypted_size))

    # Measure PQC algorithm performance
    performance_metrics = measure_performance(algorithm, payloads)

    cursor.execute("""
        INSERT INTO pqc_benchmarks (algorithm, application, execution_time, cpu_usage, memory_usage, power_usage)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (algorithm, application, performance_metrics["avg_execution_time_ms"],
          performance_metrics["avg_cpu_usage"], performance_metrics["avg_memory_usage_mb"],
          performance_metrics["avg_power_usage_watts"]))

    conn.commit()
    conn.close()

    return {"status": "completed", "pcap_file": pcap_file, "performance_metrics": performance_metrics}


# Read power stats from the Raspberry Pi
def get_power_usage():
    power_file = "/sys/class/power_supply/battery/voltage_now"
    if not os.path.exists(power_file):
        return "Not Available"  # Ensure "Not Available" is returned when power stats are missing
    with open(power_file, "r") as f:
        voltage = int(f.read().strip()) / 1e6  # Convert µV to V
    # Additional logic for power usage can be added here
    return voltage

# Function to fetch benchmark results
def get_all_benchmarks():
    """Fetch all stored benchmark results from the database."""
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM pqc_benchmarks ORDER BY timestamp DESC", conn)
    conn.close()
    return df

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
    df = get_all_benchmarks() # Calls get_all_benchmarks() to fetch benchmark results from the database
    return render_template("report.html", data=df.to_dict(orient="records"), titles=df.columns.values)
    # Renders report.html with the fetched benchmark results as tables and column titles
    # tables=[df.to_html()]: Converts the DataFrame to an HTML table
    # titles=df.columns.values: Passes column names for formatting


# Function to send execution time data as JSON for execution time bar chart
@app.route('/execution_times')
def get_execution_times():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT algorithm, execution_time FROM pqc_benchmarks", conn)
    conn.close()

    # Keep execution time in seconds (remove microsecond conversion)
    avg_exec_time = df.groupby("algorithm")["execution_time"].mean().reset_index()

    print("Execution Times API Response:", avg_exec_time.to_dict(orient="records"))  # Debugging

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