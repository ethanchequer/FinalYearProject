# app.py handles benchmarking and web routes
# imports Flask and sets up the app
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_socketio import SocketIO, emit
import time
import oqs # Python bindings for the OQS library
# import subprocess
import sqlite3 # SQLite database
import pandas as pd
import psutil
import threading
app = Flask(__name__)
socketio = SocketIO(app)

# Function to connect to the SQLite results database
def get_db_connection():
    return sqlite3.connect("results.db", check_same_thread=False)

# Function to fetch all benchmark results from the results database
def get_all_benchmarks():
    conn = get_db_connection() # Connect to the database
    df = pd.read_sql_query("SELECT * FROM benchmarks ORDER BY timestamp DESC", conn)
    # Executes an SQL query to retrieve all records from the benchmarks table
    # sorted by timestamp in descending order (newest results first)
    # Returns the results as a pandas DataFrame
    conn.close() # Closes the database connection
    return df # Returns the DataFrame containing all benchmark results


# Benchmarking function for PQC algorithms (Runs PQC Tests)
def benchmark_pqc(algorithm):
    try:
        start_time = time.time()
        start_cpu = psutil.cpu_percent(interval=None)

        if algorithm == "Kyber512":
            kem = oqs.KeyEncapsulation("Kyber512")
            public_key = kem.generate_keypair()
            ciphertext, shared_secret_enc = kem.encap_secret(public_key)
            shared_secret_dec = kem.decap_secret(ciphertext)

        elif algorithm in ["Dilithium2", "SPHINCS+-128s"]:
            sig = oqs.Signature(algorithm)
            message = b"Test message"

            public_key = sig.generate_keypair()
            signature = sig.sign(message)
            is_valid = sig.verify(message, signature, public_key)

            if not is_valid:
                return {"error": f"{algorithm} Signature Verification Test Failed!"}

        else:
            return {"error": "Invalid algorithm"}

        execution_time = time.time() - start_time
        end_cpu = psutil.cpu_percent(interval=None)

        return {
            "algorithm": algorithm,
            "time": round(execution_time, 4),
            "cpu_usage": round(end_cpu, 2),
            "power": "TBD"  # Replace with actual power measurement
        }

    except Exception as e:
        return {"error": str(e)}


# Async Function to Run Benchmarks and Update Progress
def run_benchmarks(algorithms):
    conn = get_db_connection()
    for index, algorithm in enumerate(algorithms):
        socketio.emit("progress", {"message": f"Running {algorithm}..."})
        result = benchmark_pqc(algorithm)

        if "error" not in result:
            conn.execute("INSERT INTO benchmarks (algorithm, execution_time, power_usage) VALUES (?, ?, ?)",
                         (result["algorithm"], result["time"], result["power"]))  # Includes power measurement
            conn.commit()
        else:
            print:(f"Error running {algorithm}: {result['error']}")

    conn.close()
    with app.app_context():
        socketio.emit("progress", {"message": "Completed!"})
        socketio.emit("redirect", {"url": "http://127.0.0.1:5000/report"})  # Redirect to report page


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
    return render_template("report.html", tables=[df.to_html()], titles=df.columns.values)
    # Renders report.html with the fetched benchmark results as tables and column titles
    # tables=[df.to_html()]: Converts the DataFrame to an HTML table
    # titles=df.columns.values: Passes column names for formatting

# Run Flask App
if __name__ == '__main__': # If this script is run directly, start the Flask app
    app.run(host="0.0.0.0", port=5000, debug=True) # Enable debug mode for:
                        # Automatic reloading on code changes.
                        # Error traceback in the browser when exceptions occur

# This version of the app runs the front end. The backend is not operational due to errors with the cpu usage value
# in the benchmark database and not generating a report.