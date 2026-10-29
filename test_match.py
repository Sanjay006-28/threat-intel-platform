import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from app.database import SessionLocal
from app.correlator import Correlator
from app.parsers.manager import process_log_file

db = SessionLocal()
correlator = Correlator(db)
print(f"Loaded {len(correlator.active_iocs)} IOCs.")

matches = 0
for data in process_log_file('demo_security.log'):
    if data['artifacts']:
        found = correlator.check_artifacts(data['artifacts'])
        if found:
            print(f"[*] Match: {found[0].value} in {data['raw_line']}")
            matches += 1
print(f"Total Matches: {matches}")
