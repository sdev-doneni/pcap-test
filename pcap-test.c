#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "libnet_hdr.h"

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

void printMac(u_int8_t *mac)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return;
}

void printIp(struct in_addr ip)
{
	printf("%s", inet_ntoa(ip));
}

int main(int argc, char* argv[]) {
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
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));

        if (ip_hdr->ip_p != 6)
            continue;

		printf("======================================\n");
		printf("%u bytes captured\n", header->caplen);

		printf("[ehternet header]\n");
		printf("src mac: ");
		printMac(eth_hdr->ether_shost);
		printf(" | dest mac: ");
		printMac(eth_hdr->ether_dhost);
		printf("\n");
		
		printf("[ip header]\n");
		printf("src ip: ");
		printIp(ip_hdr->ip_src);
		printf(" | dest ip: ");
		printIp(ip_hdr->ip_dst);
		printf("\n");

		printf("[tcp header]\n");
		printf("src port: %d | dest port: %d\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
	}

	pcap_close(pcap);
}
