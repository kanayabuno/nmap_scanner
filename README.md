# NMAP scanner
Flask application that can take a hostname/IP address as an input and perform NMAP scan

# Run the application
This project utilizes NMAP command line tool and Flask framework and can be run with the following:
```bash
$ python3 ./nmap_scanner/nmap_scanner.py --mysql-host "localhost" --mysql-user "root" --mysql-password "" --port 5001
```
### parameters
| Param          | Description                 | default     |
| -------------- |:---------------------------:| -----------:|
| mysql-host     | mysql host                  | "localhost" |
| mysql-user     | mysql user                  | "root"      |
| mysql-password | mysql password              | ""          |
| port           | port to run the application | "5001       |