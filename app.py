# app.py handles benchmarking and web routes
# This version of the app runs the execution time, CPU, memory and power usage for the PQC benchmarks.
import eventlet
eventlet.monkey_patch()
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_file # imports Flask and sets up the app
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
import joblib
app = Flask(__name__)
socketio = SocketIO(app)

model = joblib.load("optimal_algorithm_model_v2.pkl")

NUM_TRIALS = 10 # Define the number of trials per test to improve accuracy
APPLICATION_TYPES = ["Video Streaming", "File Transfer", "VoIP", "Web Browsing"] # Available application types for testing
ALGORITHM_MAP = {
    "SPHINCS+-128s": "SPHINCS+-SHA2-128s-simple",
}


################## DATABASES ##################
def get_db_connection():
    """ Connect to the SQLite database. """
    conn = sqlite3.connect("pqc_results.db", check_same_thread=False)
    return conn # Returns the SQLite database connection
def initialize_database():
    """ Initialize the database and tables for results storage. """
    conn = get_db_connection()
    cursor = conn.cursor()
    # Check if the 'application' column exists in pqc_benchmarks
    cursor.execute("PRAGMA table_info(pqc_benchmarks)")
    columns = [column[1] for column in cursor.fetchall()]
    if "application" not in columns:
        cursor.execute("ALTER TABLE pqc_benchmarks ADD COLUMN application TEXT")
    if "throughput" not in columns:
        cursor.execute("ALTER TABLE pqc_benchmarks ADD COLUMN throughput REAL")
    if "timeout" not in columns:
        cursor.execute("ALTER TABLE pqc_benchmarks ADD COLUMN timeout INTEGER")
    if "packet_count_requested" not in columns:
        cursor.execute("ALTER TABLE pqc_benchmarks ADD COLUMN packet_count_requested INTEGER")
    if "optimal_algorithm" not in columns:
        cursor.execute("ALTER TABLE pqc_benchmarks ADD COLUMN optimal_algorithm TEXT")
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
                timeout INTEGER,
                packet_count_requested INTEGER,
                optimal_algorithm TEXT,
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

    # Table for packet loss stats
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packet_loss_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            algorithm TEXT,
            application TEXT,
            packets_sent INTEGER,
            packets_received INTEGER,
            packet_loss_rate REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table for throughput stats
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS throughput_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            algorithm TEXT,
            application TEXT,
            throughput_kbps REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


############### LOAD AI MODEL ##################
try:
    model = joblib.load("optimal_algorithm_model_v2.pkl")
    print("[INFO] Trained model loaded successfully.")
except Exception as e:
    print(f"[ERROR] Failed to load trained model: {e}")
    model = None


############## EXTRACT FEATURES #################
def extract_features_from_db(latest_test):
    """
    Extracts the relevant features from the database row to use for prediction.
    """
    (
        id, algorithm, application, execution_time, cpu_usage, memory_usage,
        power_usage, timeout, packet_count_requested, _, optimal_algorithm
    ) = latest_test[:11]

    # Manually calculate additional features
    security_weighting = {
        'Kyber512': 1,
        'Dilithium2': 2,
        'SPHINCS+-SHA2-128s': 1
    }.get(algorithm, 0)

    application_importance = {
        'Web Browsing': 1,
        'VoIP': 2,
        'Video Streaming': 3,
        'File Transfer': 4
    }.get(application, 0)

    # Calculate packet_completion_rate correctly
    try:
        packets_sent = int(latest_test[5])  # Assuming packets_sent is at index 5
        packets_received = int(latest_test[6])  # Assuming packets_received is at index 6
        packet_count_requested = int(latest_test[8])  # Assuming packet_count_requested is at index 8
        packet_completion_rate = packets_received / max(packets_sent, 1) if packets_sent > 0 else 0
        print(f"[DEBUG] Calculated packet_completion_rate: {packet_completion_rate}")
    except (TypeError, ValueError):
        packet_completion_rate = 0

    # Set placeholders for missing metrics
    power_usage_feature = 0
    power_recorded = 1 if power_usage != "Not Available" else 0
    memory_recorded = 1 if memory_usage > 0 else 0
    total_successful = 0
    packets_failed = 0
    loss_rate = 0
    throughput_kbps = 0
    packet_count = packet_count_requested
    successful_packets = 0
    cpu_efficiency = 0
    throughput_efficiency_kbps = 0
    latency_to_throughput_ratio = 0

    # Map algorithm to one-hot encoded features with default 0
    algorithm_features = [
        1 if algorithm == "Dilithium2" else 0,
        1 if algorithm == "Kyber512" else 0,
        1 if algorithm == "SPHINCS+-SHA2-128s" else 0,
    ]

    # Map application to one-hot encoded features with default 0
    application_features = [
        1 if application == "File Transfer" else 0,
        1 if application == "Video Streaming" else 0,
        1 if application == "VoIP" else 0,
        1 if application == "Web Browsing" else 0,
    ]

    # Combine all features in the correct order
    features = [
        execution_time, cpu_usage, memory_usage, power_usage_feature,
        timeout, packet_count_requested, total_successful, packets_failed,
        loss_rate, throughput_kbps, packet_count, power_recorded, memory_recorded,
        successful_packets, cpu_efficiency, throughput_efficiency_kbps, latency_to_throughput_ratio,
        security_weighting, application_importance, *algorithm_features, *application_features, packet_completion_rate
    ]
    print(f"[DEBUG] Features prepared for prediction (including packet_completion_rate): {len(features)} - {features}")
    print(f"[DEBUG] Final feature list (length {len(features)}): {features}")
    return features


############## TRAFFIC SIMULATION ##############
def simulate_application_traffic(application):
    """Simulates traffic generation for a specific application type using subprocess."""
    try:
        if application == "Video Streaming":
            # Check if the sample video exists before streaming
            if not os.path.exists("sample_video.mp4"):
                print("[ERROR] sample_video.mp4 not found. Skipping video streaming simulation.")
                return None
            return subprocess.Popen([
                "ffmpeg", "-re", "-i", "sample_video.mp4",
                "-f", "mpegts", "udp://127.0.0.1:1234"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif application == "File Transfer":
            # Start a simple HTTP server and simulate file downloads
            server_process = subprocess.Popen(["python3", "-m", "http.server", "8080"],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)  # Allow server to start
            return subprocess.Popen([
                "bash", "-c",
                "for i in {1..10}; do curl -s http://127.0.0.1:8080/test.file > /dev/null; sleep 1; done"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif application == "Web Browsing":
            # Simulate HTTP GET requests to localhost server
            return subprocess.Popen([
                "bash", "-c",
                "for i in {1..60}; do curl -s --interface lo0 http://127.0.0.1:8080/test.html?rand=$RANDOM > /dev/null; sleep 0.5; done"
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


############ PQC ENCRYPTION/SIGNING ############
def apply_pqc_algorithm(algorithm, payload, public_key, sig_obj=None):
    """ Encrypts or signs a single payload using the selected PQC algorithm in real-time. """
    print(f"[DEBUG] apply_pqc_algorithm called with algorithm: {algorithm}")
    try:
        if algorithm == "Kyber512":
            kem = oqs.KeyEncapsulation("Kyber512")
            ciphertext, _ = kem.encap_secret(public_key)
            return ciphertext

        elif algorithm == "Dilithium2":
            if sig_obj:
                signature = sig_obj.sign(payload)
                # verified = sig_obj.verify(payload, signature, public_key)
                return signature  # if verified else None

        elif algorithm in ["SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHAKE-128s-simple"]:
            if sig_obj:
                signature = sig_obj.sign(payload)
                # verified = sig_obj.verify(payload, signature, public_key)
                return signature  # if verified else None

        return None

    except Exception as e:
        print(f"[ERROR] Encryption/Signature failed for {algorithm}: {e}")
    return None


################ PACKET CAPTURE ################
def capture_packets_with_scapy(algorithm, application, packet_count, timeout, interface):
    """Capture live network packets using scapy"""
    latency_recorded = False
    sig = None

    if algorithm == "Kyber512":
        kem = oqs.KeyEncapsulation("Kyber512")
        public_key = kem.generate_keypair()
    elif algorithm in ["Dilithium2", "SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHAKE-128s-simple"]:
        sig = oqs.Signature(algorithm)
        public_key = sig.generate_keypair()
    else:
        public_key = None
        sig = None

    total_seen = 0
    total_successful = 0

    def process_packet(packet):
        nonlocal total_seen, total_successful
        total_seen += 1  # Count all packets

        if packet.haslayer(Raw):
            print(f"[DEBUG] Raw packet captured: {packet.summary()}")
        else:
            print(f"[DEBUG] Packet seen (non-Raw): {packet.summary()}")

        payload = bytes(packet[Raw]) + b"x" * 256 if packet.haslayer(Raw) else b"x" * 256
        start = time.perf_counter()
        encrypted_data = apply_pqc_algorithm(algorithm, payload, public_key, sig)
        enc_time = (time.perf_counter() - start) * 1000  # ms

        if encrypted_data:
            total_successful += 1

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
            latency_recorded = True
            print(f"[DEBUG] Logged latency: {enc_time:.3f}ms for {algorithm} - {application}")
            conn.commit()
            conn.close()

    time.sleep(1)  # Delay to allow traffic to start
    sniff(prn=process_packet, count=packet_count, store=False, timeout=timeout, iface=interface)

    # Store packet loss stats
    loss_rate = ((total_seen - total_successful) / total_seen) if total_seen else 0
    packets_failed = total_seen - total_successful

    if not latency_recorded:
        print(f"[WARN] No latency recorded for {algorithm} - {application}")

    # Store packet loss stats
    loss_rate = ((total_seen - total_successful) / total_seen) if total_seen else 0
    packets_failed = total_seen - total_successful

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
              INSERT INTO packet_loss_stats (
          algorithm, application,
          packets_sent, packets_received, 
          packets_failed, packet_loss_rate,
          timestamp
      )
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  """, (
      algorithm, application,
      total_seen,
      total_successful,
      packets_failed,
      loss_rate
  ))
    conn.commit()
    conn.close()
    return total_seen, total_successful


################# BENCHMARKING #################
def benchmark_pqc(algorithm, application, packet_count=50, timeout=30, interface="lo0"):
    """Runs the full benchmark process with real-time traffic encryption and refined memory tracking."""
    gc.collect()
    tracemalloc.start()
    process = psutil.Process()
    start_time = time.perf_counter()
    start_cpu = process.cpu_percent(interval=None)
    start_mem = process.memory_info().vms / (1024 * 1024)  # MB

    traffic_process = simulate_application_traffic(application)
    result = capture_packets_with_scapy(algorithm, application, packet_count, timeout, interface)
    if result:
        total_seen, total_successful = result
    else:
        print(f"[WARN] capture_packets_with_scapy returned None for {algorithm} - {application}")
        total_seen, total_successful = 0, 0

    if traffic_process:
        traffic_process.terminate()

    # After capturing packets and terminating simulation
    end_time = time.perf_counter()
    end_cpu = process.cpu_percent(interval=None)
    end_mem = process.memory_info().vms / (1024 * 1024)  # MB
    tracemalloc.stop()

    # Calculate performance metrics
    execution_time = (end_time - start_time)  # in seconds
    cpu_usage = abs(end_cpu - start_cpu)  # %
    memory_usage = abs(end_mem - start_mem)  # MB

    # Calculate throughput
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT SUM(encrypted_size) FROM encrypted_traffic 
        WHERE algorithm = ? AND application = ? AND timestamp >= datetime('now', '-5 minutes')
    """, (algorithm, application))
    result = cursor.fetchone()
    conn.close()

    total_data_kb = (result[0] or 0) / 1024  # Convert bytes to KB
    throughput_kbps = total_data_kb / execution_time if execution_time > 0 else 0

    # Calculate additional features
    packets_failed = total_seen - total_successful
    loss_rate = ((total_seen - total_successful) / total_seen) if total_seen > 0 else 0
    power_usage_feature = 0  # Default placeholder value
    successful_packets = (total_successful / total_seen) * 100 if total_seen > 0 else 0
    cpu_efficiency = throughput_kbps / cpu_usage if cpu_usage > 0 else 0
    throughput_efficiency_kbps = throughput_kbps / cpu_usage if cpu_usage > 0 else 0

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT AVG(encryption_time_ms) FROM packet_latency 
        WHERE algorithm = ? AND application = ? AND timestamp >= datetime('now', '-5 minutes')
    """, (algorithm, application))
    latency_result = cursor.fetchone()
    conn.close()

    avg_latency = latency_result[0] if latency_result and latency_result[0] is not None else 0
    latency_to_throughput_ratio = avg_latency / throughput_kbps if throughput_kbps > 0 else 0

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pqc_benchmarks ORDER BY timestamp DESC LIMIT 1")
    latest_test = cursor.fetchone()
    conn.close()

    power_usage = latest_test[6] if latest_test and len(latest_test) > 6 else "Not Available"

    power_recorded = 1 if power_usage != "Not Available" else 0
    memory_recorded = 1 if memory_usage > 0 else 0

    features = [
        execution_time, cpu_usage, memory_usage, power_usage_feature,
        timeout, total_seen, total_successful, packets_failed, loss_rate,
        throughput_kbps, packet_count, power_usage_feature, memory_usage,
        successful_packets, cpu_efficiency, throughput_efficiency_kbps, latency_to_throughput_ratio,
        power_recorded, memory_recorded,
        (total_successful / total_seen) if total_seen > 0 else 0,  # completion rate
        1 if algorithm == "Dilithium2" else 0,
        1 if algorithm == "Kyber512" else 0,
        1 if algorithm == "SPHINCS+-SHA2-128s-simple" else 0,
        1 if application == "File Transfer" else 0,
        1 if application == "Video Streaming" else 0,
        1 if application == "VoIP" else 0,
        1 if application == "Web Browsing" else 0
    ]

    # Reshape and predict using the loaded model
    print(f"[DEBUG] Features prepared for prediction: {len(features)} - {features}")
    print(f"[DEBUG] Model feature names: {model.feature_names_in_ if hasattr(model, 'feature_names_in_') else 'Not Available'}")
    print(f"[DEBUG] Model expects {model.n_features_in_} features.")
    try:
        prediction = model.predict([features])[0]
        print(f"[INFO] Predicted optimal algorithm: {prediction}")
    except Exception as e:
        print(f"[ERROR] Model prediction failed: {e}")
        prediction = "Prediction Error"

    # Store the predicted optimal algorithm in the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE pqc_benchmarks 
        SET optimal_algorithm = ?
        WHERE id = (SELECT MAX(id) FROM pqc_benchmarks)
    """, (prediction,))
    conn.commit()
    conn.close()

    # Store benchmark results in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    with app.app_context():
        power_usage_data = get_cpu_usage()
        data = power_usage_data.get_json()
        power_usage = data[0].get("avg_cpu_usage", "Not Available") if data else "Not Available"

        cursor.execute("""
            INSERT INTO pqc_benchmarks (algorithm, application, execution_time, cpu_usage, memory_usage, power_usage, timeout, packet_count_requested)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            algorithm, application,
            execution_time,
            cpu_usage,
            memory_usage,
            power_usage,
            timeout,
            packet_count
        ))
        conn.commit()
        conn.close()

    # Map the algorithm name correctly
    mapped_algorithm = ALGORITHM_MAP.get(algorithm, algorithm)
    # Store throughput separately
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO throughput_stats (algorithm, application, throughput_kbps)
        VALUES (?, ?, ?)
    """, (mapped_algorithm, application, throughput_kbps))
    conn.commit()
    conn.close()

    return {
        "avg_execution_time_ms": execution_time,
        "avg_cpu_usage": cpu_usage,
        "avg_memory_usage_mb": memory_usage,
        "avg_throughput_kbps": throughput_kbps
    }


################ RUN ALL TESTS ##################
def run_all_tests():
    from threading import Thread

    def run_all():
        algorithms = ["Kyber512", "Dilithium2", "SPHINCS+-SHA2-128s-simple"]
        applications = ["Video Streaming", "File Transfer", "VoIP", "Web Browsing"]
        packet_count = 50
        timeout = 30
        interface = "lo0"

        total = len(algorithms) * len(applications)
        completed = 0

        for algo in algorithms:
            for app in applications:
                benchmark_pqc(algo, app, packet_count, timeout, interface)
                completed += 1
                percent = int((completed / total) * 100)
                socketio.emit('test_progress', {'progress': percent, 'current_test': f"{algo} - {app}"})
    Thread(target=run_all).start()
    return '', 204


################ RUN AUTO TESTS ################
def run_automated_batch(interface="lo0"):
    algorithms = ["Kyber512", "Dilithium2", "SPHINCS+-SHA2-128s-simple"]
    applications = ["Video Streaming", "File Transfer", "VoIP", "Web Browsing"]
    packet_options = [20, 50, 100, 200]
    timeout_options = [10, 30, 60]

    def run_batch():
        for algo in algorithms:
            for app in applications:
                for pkt in packet_options:
                    for to in timeout_options:
                        for i in range(3):  # Run each test 3 times
                            print(f"[PROGRESS UPDATE] Running {algo} - {app} | {pkt} pkts | {to}s timeout [Run {i+1}/3]")
                            try:
                                benchmark_pqc(algo, app, pkt, to, interface)
                                time.sleep(1)  # to prevent system overload
                            except Exception as e:
                                print(f"[ERROR] Failed: {algo} - {app}, packets={pkt}, timeout={to}, error={e}")

    # Start as background thread so server remains responsive
    thread = threading.Thread(target=run_batch)
    thread.start()

    return "Automated batch testing started."


##########
# ROUTES #
##########
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

    thread = threading.Thread(target=benchmark_pqc, args=(algorithm, application, packet_count, timeout, interface))
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
            benchmark_pqc(algorithm, app, packet_map[app], timeout_map[app], interface="lo0")
            completed += 1
            socketio.emit('test_progress', {'progress': int((completed / total) * 100), 'current_test': f"{algorithm} - {app}"})

        print(f"[DEBUG] Finished all tests for {algorithm}")

    Thread(target=run_tests).start()
    return '', 204


@app.route('/run_batch', methods=['POST'])
def trigger_batch():
    thread = threading.Thread(target=run_automated_batch, args=("lo0",))
    thread.start()
    return jsonify({"message": "Automated batch test started."})


@app.route('/export_csv')
def export_csv():
    conn = get_db_connection()
    df = pd.read_sql_query("""
    SELECT 
        b.id,
        CASE 
            WHEN b.algorithm LIKE 'SPHINCS+%' THEN 'SPHINCS+-128s'
            ELSE b.algorithm 
        END AS algorithm,
        b.application,
        b.execution_time,
        b.cpu_usage,
        b.memory_usage,
        b.power_usage,
        b.timeout,
        b.timestamp,
        ps.packets_sent,
        ps.packets_received,
        ps.packets_failed,
        ps.packet_loss_rate,
        lat.encryption_time_ms AS latency_per_test,
        th.avg_throughput_kbps,
        b.packet_count_requested
    FROM pqc_benchmarks b
    LEFT JOIN (
        SELECT algorithm, application, timestamp,
               packets_sent, packets_received,
               packets_failed, packet_loss_rate
        FROM packet_loss_stats
    ) ps ON b.algorithm = ps.algorithm AND b.application = ps.application AND b.timestamp = ps.timestamp
    LEFT JOIN (
        SELECT algorithm, application, timestamp, encryption_time_ms
        FROM packet_latency
        WHERE id IN (
            SELECT MAX(id)
            FROM packet_latency
            GROUP BY algorithm, application, timestamp
        )
    ) lat ON b.algorithm = lat.algorithm AND b.application = lat.application AND b.timestamp = lat.timestamp
    LEFT JOIN (
        SELECT algorithm, application, timestamp,
               AVG(throughput_kbps) AS avg_throughput_kbps
        FROM throughput_stats
        GROUP BY algorithm, application, timestamp
    ) th ON b.algorithm = th.algorithm AND b.application = th.application AND b.timestamp = th.timestamp       
        """, conn)

    csv_path = "pqc_dataset.csv"
    df.to_csv(csv_path, index=False)
    conn.close()
    return send_file(csv_path, mimetype='text/csv', as_attachment=True)



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


@app.route('/latency_stats')
def get_latency_stats(): # Access latency stats
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


@app.route('/throughput_stats')
def get_throughput_stats():
    conn = get_db_connection()
    df = pd.read_sql_query("""
        SELECT algorithm, application, AVG(throughput) AS avg_throughput_kbps
        FROM pqc_benchmarks
        GROUP BY algorithm, application
    """, conn)
    conn.close()
    return jsonify(df.to_dict(orient="records"))


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
                prediction = model.predict([features])[0]
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

# New route for testing all algorithms for the selected application
@app.route('/run_all_algorithms_for_application', methods=['POST'])
def run_all_algorithms_for_application():
    from threading import Thread
    application = request.json.get("application", None)

    if not application:
        return jsonify({"error": "Application not specified"}), 400

    def run_all_for_application():
        algorithms = ["Kyber512", "Dilithium2", "SPHINCS+-SHA2-128s-simple"]
        packet_count = 50
        timeout = 30
        interface = "lo0"
        results = []

        for algo in algorithms:
            print(f"[NEW TEST] Starting test for {algo} - {application}")
            benchmark_pqc(algo, application, packet_count, timeout, interface)

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
                    prediction = model.predict([features])[0]
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
    conn.close()

    applications = ["Video Streaming", "File Transfer", "VoIP", "Web Browsing"]
    visualizations = {}

    for app in applications:
        app_df = df[df["application"] == app]
        if app_df.empty:
            continue

        print(f"[DEBUG] Preparing bar chart for application: {app}")

        # Group by algorithm and calculate averages on numeric columns only
        numeric_columns = app_df.select_dtypes(include=["number"]).columns
        print(f"[DEBUG] Numeric columns for averaging: {list(numeric_columns)}")
        grouped = app_df.groupby("algorithm")[numeric_columns].mean().reset_index()
        print(f"[DEBUG] Grouped data for {app}: {grouped[['algorithm', 'cpu_usage', 'execution_time']].to_dict(orient='records')}")

        bar_chart_data = {
            "labels": grouped["algorithm"].tolist(),
            "datasets": [{
                "label": f"CPU Usage (%) for {app}",
                "data": grouped["cpu_usage"].tolist()
            }, {
                "label": f"Execution Time (s) for {app}",
                "data": grouped["execution_time"].tolist()
            }]
        }
        print(f"[DEBUG] Bar chart labels for {app}: {bar_chart_data['labels']}")
        print(f"[DEBUG] CPU Usage data for {app}: {bar_chart_data['datasets'][0]['data']}")
        print(f"[DEBUG] Execution Time data for {app}: {bar_chart_data['datasets'][1]['data']}")

        visualizations[app] = bar_chart_data

    return jsonify(visualizations)

# Initialize Database Before Running
initialize_database()


# Run Flask App
if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=8000) # If this script is run directly, start the Flask app
