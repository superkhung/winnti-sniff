#include <pcap.h>
#include <string>
#include <stdlib.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>
#include <map>
#include <string.h>
#include <stdio.h>
#include <ctime>

using namespace std;

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6
#define LOG_DIR "./log/";

struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];
	u_char  ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct sniff_ip {
	u_char  ip_vhl;
	u_char  ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	u_char  ip_ttl;
	u_char  ip_p;
	u_short ip_sum;
	struct  in_addr ip_src, ip_dst;
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;
	u_short th_dport;
	tcp_seq th_seq;
	tcp_seq th_ack;
	u_char  th_offx2;
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

map<string , int> detectlist;
FILE * fh;
int xpos, magpos1, magpos2;

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");
    fflush(stdout);
	return;
}

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	for (;;) {
		line_len = line_width % len_rem;
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	//u_char *payload;

	int size_ip;
	int size_tcp;
	int size_payload;
    char currtime[64];
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    
    sprintf(currtime, "%d-%d-%d-%d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		return;
	}

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) {
		return;
	}

	//payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    if (size_payload >= 28)
    {
        uint32_t *mpayload = (uint32_t*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        
        uint32_t xorkey_aced1984 = mpayload[2];
        uint32_t magic_aced1984 = mpayload[0] ^ mpayload[2];
        
        uint32_t xorkey_abc18cba = mpayload[1];
        uint32_t magic_abc18cba = mpayload[1] ^ mpayload[2];
        
        uint32_t xorkey = 0;
        uint32_t magic = 0;
        
        if (magic_aced1984 == 0xaced1984) //|| magic == 0xabc18cba)
        {
            xorkey = xorkey_aced1984;
            magic = magic_aced1984;
        }
        if (magic_abc18cba == 0xabc18cba)
        {
            xorkey = xorkey_abc18cba;
            magic = magic_abc18cba;
        }
        if (xorkey != 0 && magic !=0)
        {
			//uint32_t *mpayload = (uint32_t*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            for (int i = 0; i < size_payload / 4; i++)
            {
				mpayload[i] ^= xorkey;
            }
            printf("\n%d-%d-%d %d:%d:%d\t", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
            printf("%s:%d\t", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
            printf("%s:%d\t", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
            printf("magic: 0x%x\n", magic);
            if (size_payload > 28)
            {
                printf("Decrypted with xorkey: 0x%x\n", xorkey);
                print_payload((const u_char*)mpayload, size_payload);
            }
            magic = 0;
        }
    }
    fflush(stdout);
	return;
}

int main(int argc, char **argv)
{
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	char filter_exp[] = "tcp";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	int num_packets = 10;

	if (argc < 2)
	{
		printf("Usage: %s [pcap] or [interface]\n", argv[0]);
		return 0;
	}
	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL)
	{
		if (getuid() != 0)
		{
			printf("Permission denied.\n");
			return 0;
		}
		dev = argv[1];
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			net = 0;
			mask = 0;
		}

		printf("Device: %s\n", dev);
		printf("Filter expression: %s\n", filter_exp);

		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, 0, got_packet, NULL);
	pcap_freecode(&fp);
	pcap_close(handle);

	fflush(stdout);

	return 0;
}

