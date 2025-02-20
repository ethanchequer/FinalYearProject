import sqlite3

conn = sqlite3.connect("results.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("PRAGMA table_info(benchmarks);")
print(cursor.fetchall())  # Check if the columns exist
conn.close()
