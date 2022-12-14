from flask import Flask, render_template, request, jsonify, abort
from flask_mysqldb import MySQL
from datetime import datetime
import logging
import os
import argparse
import ipaddress
import mysql.connector
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers import helper

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

def nmap_scan(hostname, start, end):
    """
    Returns hostname and open ports on the host.
            Parameters:
                hostname (str): hostname/IP address
                start (int): start of port range
                end (int): end of port range

            Returns:
                (tuple): hostname, list of open ports
    """
    app.logger.debug(f"Scanning for hostname: {hostname} from {start} to {end}")
    open_ports = helper.scan_ports(hostname, start, end)
    return (hostname, open_ports)

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
        results = {}
        hostname_input = request.form["hostname"]
        input_hostnames = hostname_input.split(",")
        #remove duplicate hostnames
        input_hostnames = set(input_hostnames)
        app.logger.debug(f"input form: {hostname_input} hostnames: {input_hostnames}")

        for hostname in input_hostnames:
            app.logger.debug(f"hostname: {hostname}")
            try:
                #validate hostname
                if hostname:
                    if not helper.validate_hostname(hostname):
                        #try ip validation
                        ipaddress.ip_address(hostname)
                    else:
                        app.logger.debug(f"valid hostname")
            except ValueError:
                abort(400, "Invalid hostname/IP address, resubmit.")

        app.logger.debug(f"input hostnames: {input_hostnames}")

        threads = []
        scan_results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            for hostname in input_hostnames:
                if hostname:
                    threads.append(executor.submit(nmap_scan, hostname, 0, 1000))

                for thread in as_completed(threads):
                    hostname, open_ports = thread.result()
                    scan_results[hostname] = open_ports

        app.logger.debug(f"results: {results}")

        cursor = mysql.connection.cursor()
        for hostname, open_ports in scan_results.items():
            #get scan history for this host
            query_string = "SELECT * FROM {} WHERE hostname='{}'".format(table, hostname)
            app.logger.debug(f"query string: {query_string}")
            cursor.execute(query_string)
            data = cursor.fetchall()

            if data:
                prev_scan = data[-1][1].split(",")
                added, deleted = helper.compare_old_new(prev_scan, open_ports)
            else:
                added, deleted = [], []

            open_ports = ",".join(open_ports)
            added = ",".join(added)
            deleted = ",".join(deleted)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            query_string = "INSERT INTO {} VALUES('{}', '{}', '{}', '{}', '{}')".format(table, hostname, open_ports, added, deleted, timestamp)
            cursor.execute(query_string)

            results[hostname] = {
                "scan": open_ports,
                "added": added,
                "deleted": deleted,
                "timestamp": timestamp,
                "history": data
            }

        mysql.connection.commit()
        cursor.close()
        if not results:
            return ""
        return jsonify(results)

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