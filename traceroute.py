# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select
import statistics

# SOURCES:
# For error codes: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
# For how Ping works: https://www.minitool.com/lib/what-is-ping.html
# For what an echo reply is: http://www.networksorcery.com/enp/protocol/icmp/msg0.htm#Code
# For how traceroute works: Computer Networking: A Top Down Approach, Chapter 5.7 
# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            try:
                if len(self.__icmpTarget.strip()) > 0:
                    self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())
            except:
                print('Host not found.')

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            
            # Compare type - per assignment instructions, Echo Reply type must be 0
            if icmpReplyPacket.getIcmpType() == 0:
                icmpReplyPacket.setIcmpType_isValid(True)
            elif self.__DEBUG_IcmpPacket:
                print('Icmp Type not equal. Expected: 0, Received: ' + str(icmpReplyPacket.getIcmpType()))
                
            # Compare code - per assignment instructions, Echo Reply code must be 0
            if icmpReplyPacket.getIcmpCode() == 0:
                icmpReplyPacket.setIcmpCode_isValid(True)
            elif self.__DEBUG_IcmpPacket:
                print('Icmp Code not equal. Expected: 0, Received: ' + str(icmpReplyPacket.getIcmpCode()))
                
            # Compare identifier
            if self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier():
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
            elif self.__DEBUG_IcmpPacket:
                print('Icmp Identifier not equal. Expected: ' + str(self.getPacketIdentifier()) + ', Received: ' + str(icmpReplyPacket.getIcmpIdentifier()))
            
            # Compare sequence number
            if self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber():
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
            elif self.__DEBUG_IcmpPacket:
                print('Icmp Sequence Number not equal. Expected: ' + str(self.getPacketSequenceNumber()) + ', Received: ' + str(icmpReplyPacket.getIcmpSequenceNumber()))
            
            # Compare raw data
            if self.getDataRaw() == icmpReplyPacket.getIcmpData():
                icmpReplyPacket.setIcmpData_isValid(True)
            elif self.__DEBUG_IcmpPacket:
                print('Icmp Raw Data not equal. Expected: ' + str(self.getDataRaw()) + ', Received: ' + str(icmpReplyPacket.getIcmpData()))
            
            # Compare checksum
            if self.getPacketChecksum() == icmpReplyPacket.getIcmpHeaderChecksum():
                icmpReplyPacket.setIcmpHeaderChecksum_isValid(True)
            elif self.__DEBUG_IcmpPacket:
                print('Icmp Checksum not equal. Expected: ' + str(self.getPacketChecksum()) + ', Received: ' + str(icmpReplyPacket.getIcmpHeaderChecksum()))
                
            if icmpReplyPacket.getIcmpHeaderChecksum_isValid() and icmpReplyPacket.getIcmpData_isValid() and icmpReplyPacket.getIcmpSequenceNumber_isValid() and icmpReplyPacket.getIcmpIdentifier_isValid() and icmpReplyPacket.getIcmpCode_isValid() and icmpReplyPacket.getIcmpType_isValid():
                icmpReplyPacket.setIsValidResponse(True)
            else:
                icmpReplyPacket.setIsValidResponse(False)
            
        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self, ping=False):
            # returns typeReceived, codeReceived, RTT, recvAddr
            # created default variable ping to only be set to True when we're calling this method from Ping, and not from Traceroute.
            # this is because there is some information we would only want to print during Ping and not during Traceroute.
            
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            #print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 10
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    if ping:
                        print("  *        *        *        *        *    Request timed out.")
                    return None, None, '*', 'Request timed out.'
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    if ping:
                        print("  *        *        *        *        *    Request timed out (By no remaining time left).")
                    return None, None, '*', 'Request timed out.'

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]
                    # Get the address by name if possible, to display more meaningful information about where packet came from
                    try:
                        address = gethostbyaddr(addr[0])[0] + ' [' + addr[0] + ']'
                    except:
                        address = addr[0]
                        
                    if icmpType == 11:
                        if ping:
                            print('Time Exceeded')
                        if self.__DEBUG_IcmpPacket:
                            # Time Exceeded
                            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                    (
                                        self.getTtl(),
                                        (timeReceived - pingStartTime) * 1000,
                                        icmpType,
                                        icmpCode,
                                        address
                                    )
                                  )
                    elif icmpType == 5:
                        if ping:
                            print('Redirect')
                        if self.__DEBUG_IcmpPacket:
                            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                      (
                                          self.getTtl(),
                                          (timeReceived - pingStartTime) * 1000,
                                          icmpType,
                                          icmpCode,
                                          address
                                      )
                                  )
                    elif icmpType == 3:
                        if ping:
                            print('Destination Unreachable')                         # Destination Unreachable
                        if self.__DEBUG_IcmpPacket:
                            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                      (
                                          self.getTtl(),
                                          (timeReceived - pingStartTime) * 1000,
                                          icmpType,
                                          icmpCode,
                                          address
                                      )
                                  )

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        # only p
                        if ping:
                            icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)

                    else:
                        print("error")
                        return
                    
                    # Return packet type so that when this method is called from 
                    return icmpType, icmpCode, int((timeReceived - pingStartTime) * 1000), address   # Echo reply is the end and therefore should return
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        __IcmpType_isValid = False
        __IcmpCode_isValid = False
        __IcmpIdentifier_isValid = False
        __IcmpSequenceNumber_isValid = False
        __IcmpHeaderChecksum_isValid = False
        __IcmpData_isValid = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse
        
        def getIcmpType_isValid(self):
            return self.__IcmpType_isValid
        
        def getIcmpCode_isValid(self):
            return self.__IcmpCode_isValid
        
        def getIcmpIdentifier_isValid(self):
            return self.__IcmpIdentifier_isValid
        
        def getIcmpSequenceNumber_isValid(self):
            return self.__IcmpSequenceNumber_isValid
        
        def getIcmpHeaderChecksum_isValid(self):
            return self.__IcmpHeaderChecksum_isValid
        
        def getIcmpData_isValid(self):
            return self.__IcmpData_isValid

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue
            
        def setIcmpType_isValid(self, booleanValue):
            self.__IcmpType_isValid = booleanValue
        
        def setIcmpCode_isValid(self, booleanValue):
            self.__IcmpCode_isValid = booleanValue
        
        def setIcmpIdentifier_isValid(self, booleanValue):
            self.__IcmpIdentifier_isValid = booleanValue
        
        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.__IcmpSequenceNumber_isValid = booleanValue
        
        def setIcmpHeaderChecksum_isValid(self, booleanValue):
            self.__IcmpHeaderChecksum_isValid = booleanValue
        
        def setIcmpData_isValid(self, booleanValue):
            self.__IcmpData_isValid = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
            # TODO print expected result? pass request packet in?
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )
            if self.getIcmpType_isValid():
                print('Valid ICMP Type.')
            else:
                print('Invalid packet type: ' + str(self.getIcmpType()))
            
            if self.getIcmpCode_isValid():
                print('Valid ICMP Code.')
            else:
                print('Invalid packet code: ' + str(self.getIcmpCode()))
                
            if self.getIcmpIdentifier_isValid():
                print('Valid ICMP Identifier.')
            else:
                print('Invalid packet identifier: ' + str(self.getIcmpIdentifier()))
            if self.getIcmpSequenceNumber_isValid():
                print('Valid ICMP Sequence Number.')
            else:
                print('Invalid packet identifier: ' + str(self.getIcmpSequenceNumber()))
            # Did not include a validation for checksum as the checksum of the reply will always be different
            if self.getIcmpData_isValid():
                print('Valid ICMP Data.')
            else:
                print('Invalid data: ' + str(self.getIcmpData()))
                
            print('\n')
    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        sentPackets = 4
        receivedPackets = 0
        RTTs = []
        
        for i in range(sentPackets):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            typeReceived, codeReceived, RTT, recvAddr = icmpPacket.sendEchoRequest(True)                                                # Build IP
            
            # Keep track of # of packets received
            if typeReceived == 0:
                receivedPackets += 1
                if RTT is not None:
                    RTTs.append(RTT)

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data TODO do we need to do this?
        
        percentLost = (sentPackets - receivedPackets) / sentPackets * 100
        
        if len(RTTs) > 0:
            minRTT = min(RTTs)
            maxRTT = max(RTTs)
            meanRTT = int(statistics.mean(RTTs))
        else:   # Error handling for if sendEchoRequest() returns a Null RTT value
            minRTT = None
            maxRTT = None
            meanRTT = None
        print('Ping Statistics for ' + host + ':')
        print('\t Packets: Sent = ' + str(sentPackets) + ', Received = ' + str(receivedPackets) + ', Lost = ' + str(sentPackets - receivedPackets) + ' (' + str(percentLost) + '% loss),')
        print('Approximate round trip times in milliseconds:')
        print('\t Minimum = ' + str(minRTT) + 'ms, Maximum = ' + str(maxRTT) + 'ms, Average = ' + str(meanRTT) + 'ms')
    
    
    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Send Echo Requests with increasing TTLs
        typeReceived = 11
        codeReceived = 0
        currentTTL = 0
        sentPackets = 3

        # Each reply should be type 11 code 0, and attempt for maximum of 30 hops, similar to tracert command
        while typeReceived == 11 and codeReceived == 0 and currentTTL <= 29: 
            RTTs = []
            for i in range(sentPackets):
                
                
                # Build packet as was done in __sendIcmpEchoRequest()
                icmpPacket = IcmpHelperLibrary.IcmpPacket()
                randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                               # Some PIDs are larger than 16 bit                                              
                packetIdentifier = randomIdentifier
                packetSequenceNumber = i
    
                icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
                icmpPacket.setIcmpTarget(host)
                icmpPacket.setTtl(currentTTL + 1)
                typeReceived, codeReceived, RTT, recvAddr = icmpPacket.sendEchoRequest()  # gets type and code of reply, RTT, and recv addr
                
                # if the request timed out, hard code type 11 and code 0 to keep the loop going.                                                 
                if typeReceived is None and codeReceived is None:
                    typeReceived = 11
                    codeReceived = 0
                    RTTs.append('*')
                else:
                    RTTs.append(str(RTT) + 'ms')
                
            
            currentTTL += 1
            if len(RTTs) == 3:
                print(str(currentTTL) + '\t' + str(RTTs[0]) + '\t' + str(RTTs[1]) + '\t' + str(RTTs[2]) + '\t' + str(recvAddr))
            
        # Send requests until you get a response that is type 3 code 3, then say traceroute complete        
        print('Trace complete.')
             
        
    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()
    badCommand = True
    while badCommand:
        command = input('Enter \'ping\' or \'tracert\' followed by your desired destination hostname or IP address >> ')
        args = command.split()
        if len(args) != 2:
            print('Incorrect number of args. Example command: \'ping oregonstate.edu\'')
        else:
            if args[0].lower() == 'ping':
                badCommand = False
                icmpHelperPing.sendPing(args[1])
            elif args[0].lower() == 'tracert':
                badCommand = False
                icmpHelperPing.traceRoute(args[1])
            else:
                print('Unexpected command, expecting \'ping\' or \'tracert\'.')
    

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    #icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("oregonstate.edu")
    #icmpHelperPing.sendPing("gaia.cs.umass.edu")
    #icmpHelperPing.traceRoute("boeing.com")


if __name__ == "__main__":
    main()
