#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#pragma pack(push, 1)

// 이더넷 구조체 선언
struct ethernet {
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ether_type;
}__attribute__((__packed__));

// IP 구조체 선언
struct ip {
    uint8_t header_length:4; // NBO에 의해 version과 순서 변경
    uint8_t version:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t identification;
    uint16_t flagment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
}__attribute__((__packed__));

// TCP 구조체 선언
struct tcp {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence;
    uint32_t ack;
    uint8_t offset_reserved:4;
    uint8_t header_length:4; // NBO에 의해 offset_reversed와 순서 변경
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
}__attribute__((__packed__));

// TCP Payload 구조체 선언
struct TCP_Payload {
    uint8_t payload[4];
}__attribute__((__packed__));
#pragma pack(pop)

void usage() {
    printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

// 받아온 IP를 문자열로 변환해주는 함수
void ip_string(uint8_t *ip, char *ip_str) {
    sprintf(ip_str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

int main(int argc, char* argv[]) {

    // 구조체 객체 선언
    struct ethernet* ethheader;
    struct ip* ipheader;
    struct tcp* tcpheader;
    struct TCP_Payload* tcp_payload;

    // 출발지 IP의 문자열 변수 선언
    char src_ip_str[16];
    // 목적지 IP의 문자열 변수 선언
    char dst_ip_str[16];

	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
        }

        // Ethernet : 패킷의 가장 처음부분부터 데이터 할당
        ethheader = (struct ethernet *)packet;
        // IP : Etehrnet 헤더의 뒷부분부터 데이터 할당
        ipheader = (struct ip *)(packet + sizeof(struct ethernet));
        // TCP : IP 헤더의 뒷부분부터 데이터 할당
        tcpheader = (struct tcp *)(packet + (sizeof(struct ethernet)) + ((ipheader->header_length)*4));
        // TCP Payload : TCP 헤더의 뒷부분부터 데이터 할당
        tcp_payload = (struct TCP_Payload *)(packet + (sizeof (struct ethernet) + ((ipheader->header_length)*4) + (tcpheader->header_length *4)));

        // TCP 패킷을 캡처했을 경우
        if(ipheader->protocol == 6 && ethheader->ether_type == 0x008) {

            // 출발지 MAC 주소 출력
            printf("Src MAC : %02X %02X %02X %02X %02X %02X\n", ethheader->src_mac[0], ethheader->src_mac[1], ethheader->src_mac[2], ethheader->src_mac[3], ethheader->src_mac[4], ethheader->src_mac[5]);
            // 목적지 MAC 주소 출력
            printf("Dst MAC : %02X %02X %02X %02X %02X %02X\n", ethheader->dst_mac[0], ethheader->dst_mac[1], ethheader->dst_mac[2], ethheader->dst_mac[3], ethheader->dst_mac[4], ethheader->dst_mac[5]);

            // ip_string 함수를 통해 출발지 IP를 문자열로 변환
            ip_string(ipheader->src_ip, src_ip_str);
            // ip_string 함수를 통해 목적지 IP를 문자열로 변환
            ip_string(ipheader->dst_ip, dst_ip_str);
            // 출발지 IP 주소 출력
            printf("Src IP : %s\n", src_ip_str);
            // 목적지 IP 주소 출력
            printf("Dst IP : %s\n", dst_ip_str);

            // 출발지 포트 출력
            printf("Src Port : %d\n", ntohs(tcpheader->src_port));
            // 목적지 포트 출력
            printf("Dst Port : %d\n", ntohs(tcpheader->dst_port));

            // 데이터 길이 출력
            printf("Total Bytes : %u\n", header->caplen);

            // TCP 페이로드 출력
            int payload_length = header->caplen - (sizeof (struct ethernet) + ((ipheader->header_length)*4) + (tcpheader->header_length *4));
            if (payload_length != 0) {
                printf("TCP Payload : ");
                for(int i=0; i<payload_length; i++) {
                    if (i == 16)
                        break;
                    printf("%02X ", tcp_payload->payload[i]);
                }
                printf("\n");
            }
            printf("\n");
        }
    }
	pcap_close(pcap);
}
