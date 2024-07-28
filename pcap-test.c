#include <netinet/if_ether.h> // 이더넷 프레임 구조체 정의
#include <netinet/ether.h>    // 이더넷 유틸리티 함수
#include <netinet/tcp.h>      // TCP 헤더 구조체 정의
#include <netinet/ip.h>       // IP 헤더 구조체 정의
#include <netinet/in.h>       // 인터넷 프로토콜 정의
#include <arpa/inet.h>        // IP 주소 처리 함수
#include <stdlib.h>           // 표준 라이브러리 함수
#include <stdio.h>            // 표준 입출력 라이브러리
#include <pcap.h>             // 패킷 캡처 라이브러리

void handle_ethernet_packet(u_char *user_data, const struct pcap_pkthdr *packet_header, const u_char *packet_data) {
    struct ether_header *ethernet_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    int ip_header_size;
    int tcp_header_size;
    int total_header_size, payload_size;
    u_char *payload;

    ethernet_header = (struct ether_header *)packet_data;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip *)(packet_data + sizeof(struct ether_header));
        ip_header_size = ip_header->ip_hl * 4;

        if (ip_header->ip_p == IPPROTO_TCP) {
            tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_size);
            tcp_header_size = tcp_header->th_off * 4;

            if (packet_header->len < sizeof(struct ether_header) + ip_header_size + tcp_header_size) {
                fprintf(stderr, "Invalid packet size\n");
                return;
            }

            total_header_size = sizeof(struct ether_header) + ip_header_size + tcp_header_size;
            payload_size = packet_header->len - total_header_size;
            payload = (u_char *)packet_data + total_header_size;

            printf("SRC MAC: %s, ", ether_ntoa((struct ether_addr *)ethernet_header->ether_shost));
            printf("DST MAC: %s\n", ether_ntoa((struct ether_addr *)ethernet_header->ether_dhost));
            printf("SRC IP: %s, ", inet_ntoa(ip_header->ip_src));
            printf("DST IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("SRC PORT: %d, ", ntohs(tcp_header->th_sport));
            printf("DST PORT: %d\n", ntohs(tcp_header->th_dport));
            printf("DATA (up to 20 bytes): ");
            for (int i = 0; i < payload_size && i < 20; i++) {
                printf("%02x ", payload[i]);
            }
            printf("\n\n");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Syntax: %s <interface>\n", argv[0]);
        return 1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;

    pcap_handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, error_buffer);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", argv[1], error_buffer);
        return 2;
    }

    pcap_loop(pcap_handle, 0, handle_ethernet_packet, NULL);
    pcap_close(pcap_handle);
    return 0;
}
