#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include "custom_net.h"

// const char* ip_protocol_to_string(int protocol) {
//     switch (protocol) {
//         case IPPROTO_ICMP:
//             return "ICMP";
//         case IPPROTO_TCP:
//             return "TCP";
//         case IPPROTO_UDP:
//             return "UDP";
//         case IPPROTO_IP:
//             return "IP";
//         default:
//             return "Unknown";
//     }
// }

void got_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet)
{
    // Ethernet -> IP -> TCP/UDP -> HTTP
    ETH_Header *eth = (ETH_Header *)packet;

    printf("Ethernet Header -> From: %s\n", mac_address_to_string(eth->ether_shost)); // source mac
    printf("Ethernet Header ->   To: %s\n", mac_address_to_string(eth->ether_dhost)); // dest mac

    if (ntohs(eth->ether_type) == 0x0800) // IP Packet
    {
        IP_Header *ip = (IP_Header *)(packet + sizeof(ETH_Header));
        // ip->ip_ihl = (ip header length) / 4
        // (비트를 아끼기 위해 실제 헤더의 길이에서 값을 나눠두었다.)
        int ip_header_len = ip->iph_ihl * 4;

        printf("IP Header -> From: %s\n", inet_ntoa(ip->iph_sourceip)); // source ip
        printf("IP Header ->   To: %s\n", inet_ntoa(ip->iph_destip)); // dest ip

        // homework condition: TCP protocol
        if (ip->iph_protocol == IPPROTO_TCP)
        {
            TCP_Header *tcp = (TCP_Header *)(packet + sizeof(ETH_Header) + ip_header_len);

            printf("TCP Header -> From: %d\n", tcp->tcp_sport); // source port
            printf("TCP Header ->   To: %d\n", tcp->tcp_dport); // dest port

            int total_header_length = sizeof(ETH_Header) + ip_header_len + tcp->tcp_offx2 * 4;
            int payload_length = header->len - total_header_length;
            u_char *msg = (u_char *)(packet + total_header_length);
            printf("          MESSAGE : %s\n", msg);
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name {YOUR NIC(WINDOWS: ipconfig, LINUX/UNIX: ifconfig)}
    handle = pcap_open_live("wlo1", BUFSIZ, 1, 1000, errbuf); 
    if (handle == NULL)
    {
        pcap_perror(handle, "Error");
        exit(1);
    }

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);              
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);                    

    pcap_close(handle);   //Close the handle
    return 0;
}
