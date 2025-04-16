import sqlite3

def get_db_connection():
    """ Connect to the SQLite database. """
    conn = sqlite3.connect("data/pqc_results.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    """ Initialize the database and tables for results storage. """
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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packet_latency (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            algorithm TEXT,
            application TEXT,
            encryption_time_ms REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
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

def extract_features_from_db(row):
    """
    Extracts features from a benchmark result row for prediction.
    Assumes the row is a dictionary-like object with keys matching column names.
    """
    try:
        features = [
            row["execution_time"],
            row["cpu_usage"],
            row["memory_usage"],
        ]
        return features
    except KeyError:
        return [0, 0, 0]
