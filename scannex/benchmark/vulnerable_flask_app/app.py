"""Vulnerable Flask Benchmark Application for ScanneX Retrospective Evaluation.

Simulates a pre-patch web application containing realistic vulnerabilities:
1. SQL Injection in user lookup (/api/user)
2. Command Injection in diagnostic ping tool (/tools/ping)
3. Server-Side Template Injection (/render)
"""

import argparse
import os
import sqlite3
import subprocess
import sys
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

DB_PATH = "demo.db"


def init_db():
    """Seed benchmark database with mock records."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cur.execute("DELETE FROM users")
    cur.execute("INSERT INTO users (username, role) VALUES ('alice', 'user')")
    cur.execute("INSERT INTO users (username, role) VALUES ('admin', 'superuser')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return jsonify({"status": "running", "service": "ScanneX Benchmark Target"})


@app.route("/api/user", methods=["GET"])
def get_user():
    """VULNERABILITY 1: SQL Injection via unescaped string formatting (Bandit B608)."""
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Raw query string formatting vulnerable to SQLi
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()

    return jsonify({"query": query, "results": rows})


@app.route("/tools/ping", methods=["POST", "GET"])
def ping_tool():
    """VULNERABILITY 2: Command Injection via os.system (Bandit B605 / B602)."""
    target = request.args.get("target") or request.form.get("target", "127.0.0.1")
    # Untrusted shell command concatenation
    cmd = f"echo pinging {target}"
    os.system(cmd)
    return jsonify({"status": "executed", "target": target})


@app.route("/render", methods=["GET"])
def render_template_endpoint():
    """VULNERABILITY 3: Server-Side Template Injection (SSTI)."""
    name = request.args.get("name", "Guest")
    # Dynamic string template evaluation vulnerable to SSTI
    template = f"Hello {name}"
    return render_template_string(template)


if __name__ == "__main__":
    init_db()
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "5000")))
    args = parser.parse_args()
    app.run(host="127.0.0.1", port=args.port, debug=False)
