import sqlite3
import os
print(f"File size: {os.path.getsize('threat_intel.db')}")
conn = sqlite3.connect('threat_intel.db')
tables = conn.cursor().execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print("Tables:", tables)
