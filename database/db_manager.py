"""
db_manager.py

This module manages all interactions with the SQLite database used in the PQC benchmarking web application.
It handles database connections, schema initialization, and provides functions for data extraction and converting the
data into features for the AI model.
"""

import sqlite3  # Used for database interactions

# Establish a connection to the SQLite database
def get_db_connection():
    conn = sqlite3.connect("data/pqc_results.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Create necessary tables and add new columns to the existing pqc_benchmarks table if missing
def initialize_database():
    conn = get_db_connection()
    cursor = conn.cursor()
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
    if "packet_loss" not in columns:
        cursor.execute("ALTER TABLE pqc_benchmarks ADD COLUMN packet_loss REAL")

    # Table for storing PQC benchmark results including execution and resource usage metrics
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
            packet_loss REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Table for logging encrypted traffic sizes
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
    # Table for recording encryption timing and sizes for packet statistics
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
    # Table for tracking latency of encrypted packets
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packet_latency (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            algorithm TEXT,
            application TEXT,
            encryption_time_ms REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Table for tracking packet loss statistics
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
    # Table for logging throughput measurements per algorithm and application
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

# Extract relevant numeric features from a benchmark row for AI model input
def extract_features_from_db(row):
    try:
        features = [
            row["execution_time"],
            row["cpu_usage"],
            row["memory_usage"],
        ]
        return features
    except KeyError:
        return [0, 0, 0]
