#!/usr/bin/env python3

# Author: Maximilian von Tschirschnitz, License: CC BY-NC-SA 

# This application allows to benchmark the Bluetooth Initiator and Responder applications in this project for cycle and instruction count of their crypto operations.
# Make sure to compile the respective Responder/Initiator using make clean && MEASURE=1 make to enable the profiling.
# Run this application once as server (-s) for the Responder and once as client (-c) for the Initiator application.
# Provide both applications with a matching free port number and supply the (reachable) IP address of the server to the client
# Also make sure to provide the client application with the Bluetooth address of the servers Bluetooth device.

import sys
import os
import time
import select
import socket
import signal
import re
from subprocess import Popen, PIPE, STDOUT

TIMEOUT_SECONDS = 30

if sys.argv[1] == '-s':
    print("Running as Server")
    is_server = True
    ip = "0.0.0.0"
    port = int(sys.argv[2])
    binary = sys.argv[3]
    binary_parameters = sys.argv[4:]
elif sys.argv[1] == '-c':
    print("Running as Client")
    is_server = False
    ip = sys.argv[2]
    port = int(sys.argv[3])
    binary = sys.argv[4]
    binary_parameters = sys.argv[5:]
else:
    print("Usage: {} -s [listening port] [responder_binary] [binary parameters]\n OR {} -c [server ip] [server port] [initiator_binary] [binary parameters]".format(sys.argv[0], sys.argv[0]))
    exit(0)
    
if is_server:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))

    server.listen(5)
    print("Server listening on {} {}".format(ip, port))
    # Server (Responder) waits until Client connects
    s, addr = server.accept()
    print("Accepted Connection from {} {}".format(addr[0], addr[1]))
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    # Client connects


# Logging
log = open(os.path.basename(binary)[:-4] + ".msmt", 'a', buffering=1)

execution_num = 0

# Now both, Responder and Initiator are initialized
while(True):
    print("Running subprocess {}".format([*([binary] + binary_parameters)]))

    # The provided Initiator/Responder application is run as subprocess
    p = Popen(["timeout", str(TIMEOUT_SECONDS)] + [binary] + binary_parameters, stdout=PIPE, stderr=STDOUT, stdin=PIPE, bufsize=1, universal_newlines=True)

    instruction_count = 0
    cycle_count = 0

    write_log = True
    while True:

        # Parsing of output of Responder/Initiator to collect benchmarking data
        line = p.stdout.readline()
        print(line)
        if "instructions" in line:
            # print(line)
            num = int(re.findall(r"\d+", line)[0])
            # print(line + ": {} instructions".format(num))
            instruction_count += num

        if "cpu cycles" in line:
            # print(line)
            num = int(re.findall(r"\d+", line)[0])
            # print(line + ": {} cycles".format(num))
            cycle_count += num

        # Detect if numeric comparison is requested -> just confirm
        if "TO USER" in line:
            try:
                p.stdin.write("y\n")
                continue
            except IOError as e:
                if e.errno == errno.EPIPE or e.errno == errno.EINVAL:
                # Stop loop on "Invalid pipe" or "Invalid argument".
                # No sense in continuing with broken pipe.
                    break
                else:
                    # Raise any other error.
                    raise

        # Detect if Passkey transfer is requested -> send passkey over tcp socket
        if "Display Passkey" in line:
            passkey = re.findall(r"\d+", line)[0]
            s.send(passkey.encode())# Send passkey

        # Enter Passkey received over tcp socket
        if "Please Enter" in line:
            passkey = s.recv(6).decode()# Send passkey
            try:
                p.stdin.write(passkey + "\n")
                continue
            except IOError as e:
                if e.errno == errno.EPIPE or e.errno == errno.EINVAL:
                # Stop loop on "Invalid pipe" or "Invalid argument".
                # No sense in continuing with broken pipe.
                    break
                else:
                    # Raise any other error.
                    raise


        if "successfully opened" in line:
            print(line)
            break

    # One measurement cycle is finished -> write to logfile
    if write_log:
        print("Execution {} instruction count: {}, cycle count: {}".format(execution_num, instruction_count, cycle_count))
        log.write("{}: {} instructions, {} cpu cycles\n".format(execution_num, instruction_count, cycle_count))
        execution_num += 1

    if p.poll() is None:
        os.kill(p.pid, signal.SIGTERM)

if is_server:
    server.close()
    log.close()
