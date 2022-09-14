# NMAP scanner
Flask application that can take a hostname/IP address as an input and perform NMAP scan

### Run the application
This project utilizes NMAP command line tool and Flask framework and can be run with the following:
NOTE: Make sure you have nmap installed in your system.
```bash
#create venv
$ python3 -m venv venv
$ source venv/bin/activate
$ pip3 install -r requirements.txt
$ python3 ./nmap_scanner/nmap_scanner.py --mysql-host "localhost" --mysql-user "root" --mysql-password "" --port 5001
```
### Parameters
| Param          | Description                 | default     |
| -------------- |:---------------------------:| -----------:|
| mysql-host     | mysql host                  | "localhost" |
| mysql-user     | mysql user                  | "root"      |
| mysql-password | mysql password              | ""          |
| port           | port to run the application | "5001       |

### Run the application inside docker container
```bash
$ docker build -t nmap_scanner .
$ docker run -p 5001:5001  --expose 5001 nmap_scanner:latest --mysql-host "host.docker.internal" --mysql-user "root" --mysql-password "" --port 5001
# or
$ docker run -d -p 5001:5001  --expose 5001 nmap_scanner:latest --mysql-host "host.docker.internal" --mysql-user "root" --mysql-password "" --port 5001
```

### Run pytest
```bash
$ pytest ./tests/test_helper.py