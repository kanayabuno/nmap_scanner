from flask import Flask, render_template, request
from flask_mysqldb import MySQL
import nmap
import logging
from datetime import datetime
from helpers import helper

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'nmap'
 
mysql = MySQL(app)
table = "ports"

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/scan', methods = ['POST'])
def scan():
    app.logger.debug("scanning")

    if request.method == 'POST':
        result = []
        hostnames = request.form['hostname'].split(',')

        cursor = mysql.connection.cursor()

        nm = nmap.PortScanner()
        for hostname in hostnames:
            nm.scan(hostname, '0-4000')

            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = list(nm[host][proto].keys())
                    if lport:
                        lport.sort()
                        app.logger.debug(f"lport: {lport}")
                        for port in lport:
                            app.logger.debug(f"port: {port} state: {nm[host][proto][port]['state']}")
                            if nm[host][proto][port]['state'] == 'open':
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

            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            result.append([hostname, ",".join(open_ports), ",".join(added), ",".join(deleted), data, timestamp])

        app.logger.debug(f"result: {result}")
    
        for hostname, ports, added, deleted, data, timestamp in result:
            app.logger.debug(f"hostname: {hostname}, ports: {ports}, added: {added}, deleted: {deleted}")
            query_string = "INSERT INTO {} VALUES('{}', '{}', '{}', '{}', '{}')".format(table, hostname, ports, added, deleted, timestamp)
            cursor.execute(query_string)
        mysql.connection.commit()
        cursor.close()

        return render_template("result.html", result = result)
#CREATE TABLE ports(hostname VARCHAR(100) NOT NULL, ports VARCHAR(MAX) NOT NULL, added VARCHAR(MAX) NOT NULL, deleted VARCHAR(MAX) NOT NULL, PRIMARY KEY(hostname));

#SELECT hostname,ports,timestamp FROM ports port1 WHERE timestamp=(SELECT MAX(timestamp) FROM ports port2 WHERE port1.hostname=port2.hostname) ORDER BY hostname, ports, timestamp;