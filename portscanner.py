# Multithreaded Port Scanner
#Pratik Gade
#The practice of attempting to connect to a range of ports in sequence on a single host is commonly known as port scanning.
# This is usually associated either with malicious cracking attempts or with network administrators looking for possible vulnerabilities to help prevent such attacks.
# Port connection attempts are frequently monitored and logged by hosts. The technique of port knocking uses a series of port connections (knocks) from a client computer to enable a server connection.
from queue import Queue #Since our threads run simultaneously and scan the ports, we use queues to make sure that every port is only scanned once.
import socket #Threading will allow us to run multiple scanning functions simultaneously.
import threading #Socket will be used for our connection attempts to the host at a specific port.

target = "127.0.0.1"#Target is obviously the IP-Address or domain of the host we are trying to scan.
queue = Queue()#The queue is now empty and will later be filled with the ports we want to scan.
open_ports = []#And last but not least we have an empty list, which will store the open port numbers at the end.


#Here you can see a basic try-except block,
# in which we try to connect to our target on a specific port.
# If it works, we return True, which means that the port is open.
# Otherwise, we return False, which means that there was an error and we assume that the port is closed.
def portscan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        return True
    except:
        return False
#In this function we have defined four possible modes.
# The first mode scans the 1023 standardized ports.
# With the second mode we add the 48,128 reserved ports.
# By using the third mode we focus on some of the most important ports only.
# And finally, the fourth mode gives us the possibility to choose our ports manually. After that we add all our ports to the queue.
def get_ports(mode):
    if mode == 1:
        for port in range(1, 1024):
            queue.put(port)
    elif mode == 2:
        for port in range(1, 49152):
            queue.put(port)
    elif mode == 3:
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 443]
        for port in ports:
            queue.put(port)
    elif mode == 4:
        ports = input("Enter your ports (seperate by blank):")
        ports = ports.split()#when we enter the ports ,we are splitting our input into a list of strings
        ports = list(map(int, ports))#Therefore, we need to map the typecasting function of the integer data type to every element of the list in order to use it.
        for port in ports:
            queue.put(port)

#It is quite simple. As long as the queue is not empty, we get the next element and scan it.
# If the port is open, we print it and if it is not we print that as well.
# What we additionally do when a port is open, is adding it to our open_ports list.
def worker():
    while not queue.empty():
        port = queue.get()
        if portscan(port):
            print("Port {} is open!".format(port))
            open_ports.append(port)

#In this function, we have two parameters.
# The first one is for the amount of threads we want to start and the second one is our mode.
# We load our ports, depending on the mode we have chosen and we create a new empty list for our threads.
# Then, we create the desired amount of threads, assign them our worker function and add them to the list.
# After that, we start all our threads and let them work. They are now scanning all the ports.
# Finally, we wait for all the threads to finish and print all the open ports once again
def run_scanner(threads, mode):

    get_ports(mode)

    thread_list = []

    for t in range(threads):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

    print("Open ports are:", open_ports)

run_scanner(100, 2)