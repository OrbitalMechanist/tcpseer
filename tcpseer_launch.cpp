#include "tcpseer.cpp"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc != 7)
    {
        std::cout << "TCP SEER VER 0\n";
        std::cout << "Picks up and prints outgoing TCP traffic, intended for use on HTTP.\n";
        std::cout << "Syntax: tcpseer -a <IPv4 adress of target>"
                  << "-p {<Port to print> | 0}"
                  << "-s {<Text to look for in message> | _PRINT_ALL_}\n";
        return 0;
    }
    char correctAddrParam[] = "-a";
    char correctPortParam[] = "-p";
    char correctStringParam[] = "-s";
    if (strcmp(correctAddrParam, argv[1]) != 0 ||
        strcmp(correctPortParam, argv[3]) != 0 ||
        strcmp(correctStringParam, argv[5]) != 0)
    {
        std::cout << "bad flags\n";
        return -3;
    }

    ipv4_addr addressToListen;
    if (!inet_aton(argv[2], (in_addr *)&addressToListen))
    {
        std::cout << "Bad address\n";
        return -2;
    }

    unsigned short portToUse = strtoul(argv[4], NULL, 0);

    sniffAndPrintOutgoingTCP(addressToListen, portToUse, argv[6]);
}