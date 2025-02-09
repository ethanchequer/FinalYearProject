import sqlite3

# Connect to database (creates file if not exists)
conn = sqlite3.connect("../results.db")
cursor = conn.cursor()

# Create table for storing benchmark results
cursor.execute('''
    CREATE TABLE IF NOT EXISTS benchmarks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        algorithm TEXT NOT NULL,
        execution_time REAL NOT NULL,
        power_usage REAL NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')

# Create table for storing users (optional, if you want user accounts)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    )
''')

conn.commit()
conn.close()

print("Database initialized successfully.")
