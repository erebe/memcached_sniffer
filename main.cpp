#include <iostream>
#include <string>
#include <pcap.h>
#include <netinet/in.h>

#include "protocols_headers.h"
#include "memcached_protocol.h"


void handle_packet(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet)
{
    // Drop invalid packets
    if(packet == nullptr || header->len <= 0) return;

    //const struct protocols::ethernet *ethernet;
    const protocols::ip *ip;
    const protocols::tcp *tcp;
    const memcached::header_t* request;
    int size_ip;
    int size_tcp;

    //ethernet = (protocols::ethernet*)(packet);
    ip = (protocols::ip*)(packet + protocols::SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (protocols::tcp*)(packet + protocols::SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    request = (memcached::header_t*)(packet + protocols::SIZE_ETHERNET + size_ip + size_tcp);

    // Filter SET Request
    //if(request->magic != memcached::MSG_TYPE::Request || request->opcode != memcached::COMMAND::Set) return;
    if(request->magic != memcached::MSG_TYPE::Request && request->magic != memcached::MSG_TYPE::Response) return;

    //std::cout << "key_length " << ntohs(request->key_length) << '\n';
    //std::cout << "extra_length " << ntohs(request->extras_length) << '\n';
    std::cout << memcached::get_key(request)  << /* " value: " << /*memcached::get_value(request) <<*/ '\n';
    //std::cout << "expiration: " << ntohl(memcached::get_extra<memcached::MSG_TYPE::Request, memcached::COMMAND::Set>(request)->expiration) << '\n';


}


int main(int argc, char *argv[])
{
    pcap_t *handle;		/* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */

    /* PCAP filter that will be compiled to an eBPF filter */
    char filter_exp[128];
    snprintf(filter_exp, sizeof(filter_exp), "port %s and (((ip[2:2] - ((ip[0] & 0x0f) << 2)) - ((tcp[12] & 0xf0 ) >> 2)) > 0)", argv[2]);

    /* Find the properties for the device */
    char* dev = argv[1]; /* The device to sniff on */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session */
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }


    pcap_loop(handle, -1, handle_packet, NULL);


    /* And close the session */
    pcap_close(handle);
    return(0);
}