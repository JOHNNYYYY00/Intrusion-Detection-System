#include <stdio.h>
#include <sys/socket.h>
#include "network.h"
#include <pcap.h>
#include <sys/types.h>
#include <systemd/sd-journal.h>
#include "logs.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
	
	const struct sniff_ethernet *ethernet ; 
	const struct sniff_ip *ip ; 
	const struct sniff_tcp *tcp ; 
	const u_char *payload ;
	u_int size_ip ; 
	u_int size_tcp  ; 
//	u_short src_port = ntohs(tcp->th_sport) ; 
//	u_short des_port = ntohs(tcp->th_dport) ;



		ethernet = (struct sniff_ethernet*)(packet) ; 
		ip = (struct sniff_ip*)(packet+SIZE_ETHERNET) ; 
		size_ip = IP_HL(ip)*4 ; 
		if(size_ip<20){
			printf("  Invalid IP HL\n  ") ;
			return ; 
		}
		tcp=(struct sniff_tcp*)(packet+SIZE_ETHERNET + size_ip) ; 
		size_tcp = TH_OFF(tcp)*4; 
		if(size_tcp <20) {
			printf("Invalid TCP header") ; 
			return ; 
		} 

		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp) ;
	printf("\n------------------------------\n") ; 
	printf("The source IP address    : %s\n" ,inet_ntoa(ip->ip_src))  ; 
	printf("The dest IP address 	 : %s\n", inet_ntoa(ip->ip_dst)) ;
	printf("The source MAC address	 : %2x:%2x:%2x:%2x:%2x:%2x\n",
			ethernet->ether_shost[0],
	       		ethernet->ether_shost[1],
			ethernet->ether_shost[2],
			ethernet->ether_shost[3],
			ethernet->ether_shost[4],
			ethernet->ether_shost[5]) ;
//	printf("The source port		 : %d\n", src_port ) ; 
//	printf("Thee destination port  	 : %d\n", des_port) ; 
	printf(" The TCP SEQ number	 : %d\n" , tcp->th_seq) ;
	send_message() ; 	


		return  ;



}
