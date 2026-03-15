"""Shared fixtures for DepGra tests."""

import sys
import os

# Ensure the backend package root is on sys.path so that
# ``import parsers``, ``import graph``, etc. work the same way they do
# when the application is started from the backend directory.
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
