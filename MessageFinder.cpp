
/*PROJEKT OINS*/

/*STEGANOGRAFIA*/

//Michal Kocon
//Mateusz Chomiczewski

#include <string>
#include <iostream>

#include <cstdint>
#include "pcap.h"

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 3)


/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

int main(int argc, char *argv[])
{
	
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *data;		/* The actual packet */

							/* Define the device */

							/* Open the session in promiscuous mode */
	if (argc < 2) {
		std::cout << "Podaj sciezke pliku pcap jako argument" << std::endl;
		//return 0;
	}

	std::string file = argv[1];
	std::cout << file << std::endl;
	char errbuff[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(file.c_str(), errbuff);
	if (handle == NULL) {
		std::cerr << "Couldn't open pcap file: " << errbuff << std::endl;
		exit(EXIT_FAILURE);
	}

	int packet_det = 0; // detected packets with hidden transmission
	int packet_num = 0; // total number of red packets
	unsigned char id_last = 0;
	unsigned char* id = NULL;
	bool id_last_initialized = false;
	while (true) {
		data = pcap_next(handle, &header);


		if (data == NULL || packet_num > 2000) { // analyze first 2000 packets for hidden transmission (analyzing whole pcap is very slow)
			std::cout << "Nie znaleziono ukrytej transmisji!" << std::endl;
			system("pause");
			pcap_close(handle);
			return 0;
		}

		++packet_num;

		//get pointers to ip and tcp headers
		struct sniff_ip *ip = (struct sniff_ip*)(data + SIZE_ETHERNET); //IP header
		int size_ip = IP_HL(ip) * 4;
		struct sniff_tcp* tcp = (struct sniff_tcp*)(data + SIZE_ETHERNET + size_ip); //tcp header

		if (header.len > SIZE_ETHERNET + size_ip && tcp->th_sport == 16415) { //checks for hidden message when frame contains payload and port is 8000 (16415 if 2 bits are swapped)
			id = reinterpret_cast<unsigned char*>(&(ip->ip_id));
			if (id_last_initialized) { //skip searching for hidden messagage with 1st run
				id_last_initialized = false;
				id_last = id[1];
			}
			else {
				if ((id[1] - id_last) == 2) {
					++packet_det;
				}
				if (packet_det > 50) {
					std::cout << "Znaleziono ukryta transmisje!" << std::endl;
					system("pause");
					pcap_close(handle);
					return 0;
				}
				else {
					id_last = id[1];
				}
			}
			
		}
		//std::cout << std::hex << ip->ip_id << " " << tcp->th_sport << std::endl;
	}

	pcap_close(handle);
	return(0);
}

