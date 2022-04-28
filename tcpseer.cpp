//I'm not quite sure if all of these are necessary.
//I'd rather be safe than sorry.
#include <cstdio>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <algorithm>
#include "findSubstring.c"

#define MASK_BYTE_FRONT_HALF 0xf0
#define MASK_BYTE_REAR_HALF 0x0f
#define MASK_BYTE_LAST_TWO 0x03
#define MASK_BYTE_LAST_FIVE 0x1f

#define PACKET_MAX_SIZE 65535
#define SOCKET_BUFFER_MAX PACKET_MAX_SIZE

/* Same as an inet_addr but split into four separate bytes for convenience.
Can be passed in to (some, but probably most) inet_addr functions.*/
struct ipv4_addr
{
    unsigned char b1;
    unsigned char b2;
    unsigned char b3;
    unsigned char b4;
};

//IPV4 packet. Warning: created with the maximum possible size for ease of use.
struct Packet
{
    unsigned char version;
    unsigned char headerLength;
    unsigned char dscp;
    unsigned char ecn;
    unsigned short packetLength;
    unsigned short identification;
    unsigned char flags;
    unsigned short offset;
    unsigned char timeToLive;

    unsigned char protocol;
    unsigned short headerChecksum;
    ipv4_addr sourceIP;
    ipv4_addr destIP;
    unsigned char data[PACKET_MAX_SIZE - 20];
};

/*TCP message. Should be placed in Packet struct's data field and cast to
if protocol is 6 (TCP).
Warning: created with maximum possible (under ipv4) size for ease of use. */
struct TCPsegment
{
    unsigned short sourcePort;
    unsigned short destPort;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char dataOffset;
    unsigned short flags;
//use following macros to extract flags with binary AND. OR to combine flags.
#define TCP_FLAG_FIN 1
#define TCP_FLAG_SYN 2
#define TCP_FLAG_RST 4
#define TCP_FLAG_PSH 8
#define TCP_FLAG_ACK 16
#define TCP_FLAG_URG 32
#define TCP_FLAG_ECE 64
#define TCP_FLAG_CWR 128
#define TCP_FLAG_NS 256
    unsigned short windowSize;
    unsigned short checksum;
    unsigned short urgentPointer;
    unsigned char data[PACKET_MAX_SIZE - 20 - 20];
};

typedef int Socket;

void printBuffer(char *buffer, short bufferByteSize, char numColumns = 4)
{
    for (size_t i = 0; i < bufferByteSize;)
    {
        for (char j = 0; j < numColumns; j++)
        {
            std::cout << std::hex << (0xff & (unsigned int)buffer[i]) << "\t";
            i++;
        }
        std::cout << std::dec << std::endl;
    }
}

void printTCPData(TCPsegment packet, unsigned short dataLength)
{
    for (unsigned short i = 0; i < dataLength; i++)
    {
        std::cout << (char)packet.data[i];
    }
    std::cout << std::endl;
}

bool isIPV4adressEqual(ipv4_addr in1, ipv4_addr in2)
{
    return in1.b1 == in2.b1 && in1.b2 == in2.b2 && in1.b3 == in2.b3 && in1.b4 == in2.b4;
}

//seems to be working fine but I couldn't test all the fields.
Packet parseSniffedPacket(unsigned char *buffer, short bufferByteSize)
{

    Packet result;

    memset(&result, 0, sizeof(Packet));

    result.version = (buffer[0] & MASK_BYTE_FRONT_HALF) >> 4;
    result.headerLength = buffer[0] & MASK_BYTE_REAR_HALF;
    result.dscp = buffer[1] >> 2;
    result.ecn = buffer[1] & MASK_BYTE_LAST_TWO;
    result.packetLength = (buffer[2] << 8) + buffer[3];
    result.identification = (buffer[4] << 8) + buffer[5];
    result.flags = buffer[6] >> 5;
    result.offset = ((buffer[6] & MASK_BYTE_LAST_FIVE) << 8) + buffer[7];
    result.timeToLive = buffer[8];
    result.protocol = buffer[9];
    result.headerChecksum = (buffer[10] << 8) + buffer[11];
    result.sourceIP.b1 = buffer[12];
    result.sourceIP.b2 = buffer[13];
    result.sourceIP.b3 = buffer[14];
    result.sourceIP.b4 = buffer[15];
    result.destIP.b1 = buffer[16];
    result.destIP.b2 = buffer[17];
    result.destIP.b3 = buffer[18];
    result.destIP.b4 = buffer[19];
    memcpy(result.data, buffer + 20, bufferByteSize - 20);
    return result;
}

//the only fields I'm *fully* certain of here are the ports.
TCPsegment parseTCPsegment(unsigned char *buffer, short bufferByteSize)
{

    TCPsegment result;

    memset(&result, 0, sizeof(TCPsegment));

    result.sourcePort = (buffer[0] << 8) + buffer[1];
    result.destPort = (buffer[2] << 8) + buffer[3];
    result.sequence = (buffer[4] << 24) + (buffer[5] << 16) + (buffer[6] << 8) + buffer[7];
    result.acknowledge = (buffer[8] << 24) + (buffer[9] << 16) + (buffer[10] << 8) + buffer[11];
    result.dataOffset = buffer[12] >> 4;
    result.flags = ((buffer[12] & 1) << 8) + buffer[13];
    result.windowSize = (buffer[14] << 8) + buffer[15];
    result.checksum = (buffer[16] << 8) + buffer[17];
    result.urgentPointer = (buffer[18] << 8) + buffer[19];
    memcpy(result.data, buffer + 20, bufferByteSize - 20);

    return result;
}

int sniffAndPrintOutgoingTCP(ipv4_addr targetIP, unsigned short targetPort, char searchItem[])
{
    Socket listenSock;
    listenSock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (listenSock == -1)
    {
        perror("Unable to create socket");
        return listenSock;
    }
    bool stop = false;

    bool allPorts = targetPort == 0;
    char printAllMessage[] = "_PRINT_ALL_";
    bool printAll = strcmp(searchItem, printAllMessage) == 0;

    int receiveResult;

    unsigned char *receiveBuffer;
    receiveBuffer = (unsigned char *)malloc(SOCKET_BUFFER_MAX);

    //some of this *might* be leaking memory but I couldn't find if it does
    while (!stop)
    {
        receiveResult = recvfrom(listenSock, receiveBuffer, SOCKET_BUFFER_MAX, 0, 0, 0);
        Packet currentPacket = parseSniffedPacket(receiveBuffer, receiveResult);
        char packetSenderAddrForPrint[16];
        inet_ntop(AF_INET, &(currentPacket.sourceIP), packetSenderAddrForPrint, 16);
        char packetReceiverAddrForPrint[16];
        inet_ntop(AF_INET, &(currentPacket.destIP), packetReceiverAddrForPrint, 16);

        if (currentPacket.version == 4 && isIPV4adressEqual(currentPacket.sourceIP, targetIP))
        {
            if (currentPacket.protocol == 6)
            {
                TCPsegment tempTCP = parseTCPsegment(currentPacket.data, receiveResult - 20);
                memcpy(currentPacket.data,
                       (char *)&(tempTCP),
                       receiveResult - currentPacket.offset * 4);
                if (
                    (allPorts || (*(TCPsegment *)&currentPacket.data).destPort ==
                                     targetPort) &&
                    (printAll || findSubstring((char *)(*(TCPsegment *)&currentPacket.data).data, searchItem)))
                {
                    std::cout << "Intercepted a message containing \""
                              << searchItem << "\":" << std::endl;
                    printTCPData(*(TCPsegment *)&(currentPacket.data), receiveResult - 20 - 20);
                    std::cout << "\n------------------------------" << std::endl;
                }
            }
        }
    }

    return 0;
}