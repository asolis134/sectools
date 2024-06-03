timed_monitor.py
In order to use this tool you will need to have
  -python 3 ( tested on 3.11.0)
  -you will need scapy
      - pip install scapy
  -you will need psutil
      - pip install psutil


Once installed you will run the code from the directory
  -python .\timed_monitor.py 127.0.0.1 20
  -replace 127.0.0.1 with you source IP address


sys_eval.py
This is pretty straight forward. It will get a list of 
  - startup program
  - installed programs
  - scheduled task
  - services

It also demonstrates how the mames of software can be submitted to NVD to find vulnerabilities