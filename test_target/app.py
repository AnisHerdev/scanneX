"""Sample Target Web Application for ScanneX testing.

Contains realistic security vulnerabilities:
1. SQL Injection via string formatting (/api/user)
2. Command Injection via os.system (/tools/ping)
3. Server-Side Template Injection via render_template_string (/render)
"""

import argparse
import os
import sqlite3
import subprocess
import sys
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)
DB_FILE = "test_app.db"


def init_db():
    """Create local SQLite database with test users."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cur.execute("DELETE FROM users")
    cur.execute("INSERT INTO users (username, role) VALUES ('admin', 'superuser')")
    cur.execute("INSERT INTO users (username, role) VALUES ('developer', 'engineer')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return jsonify({"status": "active", "service": "Custom Test Application"})


@app.route("/api/user", methods=["GET"])
def get_user():
    """VULNERABILITY: Raw query formatting leading to SQL Injection."""
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Vulnerable sink: string concatenation in query
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    cur.execute(query)
    results = cur.fetchall()
    conn.close()

    return jsonify({"query": query, "results": results})


@app.route("/tools/ping", methods=["POST", "GET"])
def ping():
    """VULNERABILITY: Shell command execution with untrusted input."""
    target = request.args.get("target") or request.form.get("target", "127.0.0.1")

    # Vulnerable sink: os.system shell invocation
    cmd = f"echo pinging {target}"
    os.system(cmd)

    return jsonify({"status": "ping_sent", "target": target})


@app.route("/render", methods=["GET"])
def render_profile():
    """VULNERABILITY: Unescaped template string evaluation (SSTI)."""
    name = request.args.get("name", "Guest")

    # Vulnerable sink: format string in render_template_string
    template = f"Hello {name}"
    return render_template_string(template)


if __name__ == "__main__":
    init_db()
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "5000")))
    args = parser.parse_args()
    app.run(host="127.0.0.1", port=args.port, debug=False)
