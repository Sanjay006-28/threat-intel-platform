#!/usr/bin/env python
"""
SENTINEL - Database Backup & Disaster Recovery CLI Wrapper.
Delegates to scripts/manage_backup.py for backward compatibility.
"""
import sys
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from scripts.manage_backup import main

if __name__ == "__main__":
    main()

