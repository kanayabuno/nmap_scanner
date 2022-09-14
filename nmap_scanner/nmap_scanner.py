from flask import Flask, render_template, request, jsonify, abort
from flask_mysqldb import MySQL
from datetime import datetime
import nmap
import logging
import os
import argparse
import ipaddress
import mysql.connector

from helpers import helper

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

def nmap_scan(hostname):
    """A function that scans for open ports on hostname using nmap

    Args:
        hostname: hostname/IPaddress str
    Returns:
        a dictionary of scan resuslt
    """
    cursor = mysql.connection.cursor()
    result = {}
    nm = nmap.PortScanner()
    nm.scan(hostname, "0-1000")

    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = list(nm[host][proto].keys())
            if lport:
                lport.sort()
                app.logger.debug(f"lport: {lport}")
                for port in lport:
                    app.logger.debug(f"port: {port} state: {nm[host][proto][port]['state']}")
                    if nm[host][proto][port]["state"] == "open":
                        app.logger.debug(f"port: {port} state: {nm[host][proto][port]['state']}")
                        open_ports.append(str(port))
    query_string = "SELECT * FROM {} WHERE hostname='{}'".format(table, hostname)
    app.logger.debug(f"query string: {query_string}")
    cursor.execute(query_string)
    data = cursor.fetchall()

    if data:
        prev_scan = data[-1][1].split(",")
        added, deleted = helper.compare_old_new(prev_scan, open_ports)
    else:
        added, deleted = [], []

    result[hostname] = {
        "scan": ",".join(open_ports),
        "added": ",".join(added),
        "deleted": ",".join(deleted),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "history": data
    }
    return result

@app.route("/")
def index():
    """This renders input form"""
    return render_template("input_form.html")

@app.route("/scan", methods = ["POST"])
def scan():
    """API for scanning open ports using nmap
    
    POST: perform nmap scan on hostname/IP address
    """
    app.logger.debug("scanning")

    if request.method == "POST":
        hostname_input = request.form["hostname"]

        try:
            #validate hostname
            if not helper.validate_hostname(hostname_input):
                #try ip validation
                ipaddress.ip_address(hostname_input)
        except ValueError:
            abort(400, "Invalid hostname/IP address, resubmit.")            

        hostname = request.form["hostname"]
        cursor = mysql.connection.cursor()

        result = nmap_scan(hostname)
        app.logger.debug(f"result: {result}")

        if result.get(hostname):
            ports = result[hostname].get("scan", "")
            added = result[hostname].get("added", "")
            deleted = result[hostname].get("deleted", "")
            timestamp = result[hostname].get("timestamp", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

            query_string = "INSERT INTO {} VALUES('{}', '{}', '{}', '{}', '{}')".format(table, hostname, ports, added, deleted, timestamp)
            cursor.execute(query_string)
        mysql.connection.commit()
        cursor.close()

        return jsonify(result)
#CREATE TABLE ports(hostname VARCHAR(100) NOT NULL, ports VARCHAR(MAX) NOT NULL, added VARCHAR(MAX) NOT NULL, deleted VARCHAR(MAX) NOT NULL, PRIMARY KEY(hostname));

#SELECT hostname,ports,timestamp FROM ports port1 WHERE timestamp=(SELECT MAX(timestamp) FROM ports port2 WHERE port1.hostname=port2.hostname) ORDER BY hostname, ports, timestamp;

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="nmap scanner")
    parser.add_argument("--mysql-host", default="localhost")
    parser.add_argument("--mysql-user", default="root")
    parser.add_argument("--mysql-password", default="")
    parser.add_argument("--port", default=5001)
    args = parser.parse_args()

    mysql_host = args.mysql_host
    mysql_user = args.mysql_user
    mysql_password = args.mysql_password
    mysql_db = "nmap"

    app.config['MYSQL_HOST'] = mysql_host
    app.config['MYSQL_USER'] = mysql_user
    app.config['MYSQL_PASSWORD'] = mysql_password
    app.config['MYSQL_DB'] = 'nmap'
    app.config['JSON_SORT_KEYS'] = False

    mydb = mysql.connector.connect(
        host = mysql_host,
        user = mysql_user,
        password = mysql_password
    )
    table = "ports"

    cursor = mydb.cursor()
    query_string = "CREATE DATABASE IF NOT EXISTS {}".format(mysql_db)
    cursor.execute(query_string)
    query_string = "USE {}".format(mysql_db)
    cursor.execute(query_string)
    query_string = "CREATE TABLE IF NOT EXISTS {}(hostname VARCHAR(256) NOT NULL, ports TEXT(16383) NOT NULL, added TEXT(16383) NOT NULL, deleted TEXT(16383) NOT NULL, timestamp TIMESTAMP NOT NULL)".format(table)
    cursor.execute(query_string)
    mydb.commit()
    cursor.close()
    
    mysql = MySQL(app)

    port = int(os.environ.get('PORT', args.port))
    app.run(debug=True, host='0.0.0.0', port=port)
    app.logger.debug(f"app running at port:{port} args: mysql_host:{mysql_host}, mysql_user:{mysql_user}, mysql_password:{mysql_password}")