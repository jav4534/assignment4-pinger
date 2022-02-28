#Author: jav4534
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |     Type(8)   |     Code(0)   |          Checksum             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |           Identifier          |        Sequence Number        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                             Payload                           |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

from socket import *
import os
import sys
import struct
import time
import select
import binascii
import statistics
# Should use stdev

ICMP_ECHO_REQUEST = 8


def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer



def receiveOnePing(mySocket, ID, timeout, destAddr):
    #print("***** ***** receiveOnePing ***** *****")

    timeLeft = timeout

    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        #print("whatReady")
        #print(whatReady)
        #print("howLongInSelect")
        #print(howLongInSelect)
        if whatReady[0] == []:  # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fill in start
        #ipHeader = recPacket[:20]
        #print(ipHeader)
        #ipHeaderVersion, ipHeaderTypeOfSvc, ipHeaderLength, ipHeaderIdID, \
        #ipHeaderFlags, ipHeaderTTL, ipHeaderProtocol, ipHeaderChecksum, \
        #ipHeaderSrcIP, ipHeaderDestIP = struct.unpack(
        #    "!BBHHHBBHII", ipHeader
        #)

        icmpHeader = recPacket[20:28]
        type, code, checksum, processID, sequence = struct.unpack("bbHHh", icmpHeader)

        #print("type:")
        #print(type)
        #print("code:")
        #print(code)
        #print("checksum:")
        #print(checksum)
        #print("processID:")
        #print(processID)
        #print("sequence #:")
        #print(sequence)

        if processID == ID:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
            return timeReceived - timeSent

        # Fetch the ICMP header from the IP packet
        #print(ID)
        #print("received Packet:")
        #print(recPacket)
        #print("addr:")
        #print(addr)
        #recv1 = clientSocket.recv(1024).decode()

        # Fill in end
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, id):
    #print("***** ***** sendOnePing ***** *****")
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    #myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
    #print("header: ")
    #print(header)
    data = struct.pack("d", time.time())
    #print("data: ")
    #print(data)
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
    #print("myChecksum: ")
    #print(myChecksum)
    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)


    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, id, 1)
    #print("header: ")
    #print(header)
    #print("data: ")
    #print(data)
    packet = header + data

    #print("packet: ")
    #print(packet)

    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str


    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.

def doOnePing(destAddr, timeout):
    #print("***** doOnePing *****")
    icmp = getprotobyname("icmp")


    # SOCK_RAW is a powerful socket type. For more details:   http://sockraw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)

    processID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, processID)
    delay = receiveOnePing(mySocket, processID, timeout, destAddr)
    mySocket.close()
    return delay


def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,  	# the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")
    vars = []
    temp = []
    # Calculate vars values and return them
    #  vars = [str(round(packet_min, 2)), str(round(packet_avg, 2)), str(round(packet_max, 2)),str(round(stdev(stdev_var), 2))]
    # Send ping requests to a server separated by approximately one second
    for i in range(0,4):
        delay = doOnePing(dest, timeout)*1000*1000
        #print("delay:")
        print(delay)
        temp.append(delay)
        time.sleep(1)  # one second

    vars = [str(round(min(temp), 2)), str(round((sum(temp) / len(temp)), 2)), str(round(max(temp), 2)),str(round(statistics.stdev(temp), 2))]
    print(vars)

    return vars

if __name__ == '__main__':
    ping("google.co.il")
