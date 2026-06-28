"""
Production WSGI entrypoint for ThreatLens.
"""

from app import app

if __name__ == "__main__":
    app.run()
