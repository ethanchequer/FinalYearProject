# app.py handles benchmarking and web routes
# imports Flask and sets up the app
from flask import Flask, request, jsonify, render_template
import time
import oqs # Python bindings for the OQS library
import subprocess
import sqlite3 # SQLite database
import pandas as pd

app = Flask(__name__)

# Function to connect to the SQLite results database
def get_db_connection():
    return sqlite3.connect("results.db")

# Function to fetch all benchmark results from the results database
def get_all_benchmarks():
    conn = get_db_connection() # Connect to the database
    df = pd.read_sql_query("SELECT * FROM benchmarks ORDER BY timestamp DESC", conn)
    # Executes an SQL query to retrieve all records from the benchmarks table
    # sorted by timestamp in descending order (newest results first)
    # Returns the results as a pandas DataFrame
    conn.close() # Closes the database connection
    return df # Returns the DataFrame containing all benchmark results

# Home Page (Frontend)
# Renders index.html when a user visits /
@app.route('/') # Defines the route for the home page (/)
def home():
    return render_template("index.html") # When a user visits /, renders index.html (frontend webpage)


# Benchmark Page (Runs PQC Tests)

@app.route('/benchmark', methods=['POST']) # Creates a /benchmark API route that accepts POST requests
def benchmark():
    data = request.json
    algorithm = data.get("algorithm")

    if not algorithm:
        return jsonify({"error": "No algorithm selected"}), 400

    result = benchmark_pqc(algorithm)

    # Log benchmark results in the database
    if "error" not in result:
        conn = get_db_connection()
        conn.execute("INSERT INTO benchmarks (algorithm, execution_time) VALUES (?, ?)",
                     (result["algorithm"], result["time"]))
        conn.commit()
        conn.close()

    return jsonify(result)


# Benchmarking function for PQC algorithms
def benchmark_pqc(algorithm):
    try:
        start_time = time.time()

        if algorithm == "Kyber512":
            kem = oqs.KeyEncapsulation("Kyber512")
            public_key = kem.generate_keypair()
            ciphertext, shared_secret_enc = kem.encap_secret(public_key)
            shared_secret_dec = kem.decap_secret(ciphertext)

        elif algorithm in ["Dilithium2", "SPHINCS+-128s"]:
            sig = oqs.Signature(algorithm)
            message = b"Test message"
            public_key, secret_key = sig.generate_keypair()
            signature = sig.sign(message, secret_key)
            is_valid = sig.verify(message, signature, public_key)

        else:
            return {"error": "Invalid algorithm"}

        execution_time = time.time() - start_time

        return {
            "algorithm": algorithm,
            "time": round(execution_time, 4),
            "power": "N/A"  # Placeholder for power monitoring
        }

    except Exception as e:
        return {"error": str(e)}


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
    app.run(debug=True) # Enable debug mode for:
                        # Automatic reloading on code changes.
                        # Error traceback in the browser when exceptions occur
