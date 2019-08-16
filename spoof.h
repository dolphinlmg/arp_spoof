#pragma once
#include <iostream>
#include <cstring>
#include <pcap/pcap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <unistd.h>

#pragma pack(push, 1)

typedef struct {
    uint8_t dMac[6];
    uint8_t sMac[6];
    uint16_t ether_type;
} etherHeader;

typedef struct {
    uint16_t hw_type;
    uint16_t protocol;
    uint8_t hw_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} arpHeader;

typedef struct {
    uint8_t sender_ip[4];
    uint8_t sender_mac[6];
    uint8_t target_ip[4];
    uint8_t target_mac[6];
} session;

#pragma pack(pop)

extern const char* dev;
extern pcap_t* handle;
extern uint8_t* myIp;
extern uint8_t* myMac;

void dumpPacket(uint8_t* packet, size_t length);
void dumpPacket(const uint8_t* packet, size_t length);
void usage();
void setMac(session* data);
void getMac(uint8_t* ip, uint8_t* mac);
void setMyMac();
void setMyIP();
void setARPPacketHeaders(etherHeader* eth, arpHeader* arp, session* data);
bool hasToRelay(session* data, const uint8_t* packet);
uint8_t* parseIP(const char* ip);
uint8_t* relayPacket(session* data, const uint8_t* packetm, size_t len);
uint8_t* makeARPPacket(etherHeader* eth, arpHeader* arp);
