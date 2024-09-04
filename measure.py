#!/usr/bin/env python3

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
    ip = "127.0.0.1"
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
    s, addr = server.accept()
    print("Accepted Connection from {} {}".format(addr[0], addr[1]))
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

log = open(os.path.basename(binary)[:-4] + ".msmt", 'a', buffering=1)

execution_num = 0

while(True):

    print("Running subprocess {}".format([*([binary] + binary_parameters)]))

    p = Popen([binary] + binary_parameters, stdout=PIPE, stderr=STDOUT, stdin=PIPE, bufsize=1, universal_newlines=True)

    # poll_obj = select.poll()
    # poll_obj.register(p.stdout, select.POLLIN)
    timeout = time.time() + TIMEOUT_SECONDS
    instruction_count = 0

    while True:
        # Stop process gracefuly after time-limit
        if(time.time() > timeout):
            p.send_signal(signal.SIGINT)
            break

        line = p.stdout.readline()

        if "instructions" in line:
            # print(line)
            num = int(re.findall(r"\d+", line)[0])
            # print(line + ": {} instructions".format(num))
            instruction_count += num

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


        if "successfully opened" in line:
            print(line)
            p.kill()
            break

    print("Execution {} instruction count: {}".format(execution_num, instruction_count))
    log.write("{}\n".format(instruction_count))
    execution_num += 1

if is_server:
    server.close()
    log.close()
