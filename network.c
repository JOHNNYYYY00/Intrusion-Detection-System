#include <stdio.h>
#include <sys/socket.h>
#include "network.h"
#include <pcap.h>
#include <sys/types.h>
#include <systemd/sd-journal.h>
#include "logs.h"
#include <stdlib.h>
#include <regex.h> 
#include <stdbool.h> 
#include <string.h> 

int syn_number  ; 
int *synp = &syn_number ; 



void check_arp() ; 
void check_dupe(char devices[][256], int length) ; 
void check_tcp(struct sniff_tcp *tcp); 


void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){


	
	const struct sniff_ethernet *ethernet ; 
	const struct sniff_ip *ip ; 
	const struct sniff_tcp *tcp ; 
	const u_char *payload ;
	u_int size_ip ; 
	u_int size_tcp  ;
	char* msg_buf = malloc(1024) ; 
//	u_short src_port = ntohs(tcp->th_sport) ; 
//	u_short des_port = ntohs(tcp->th_dport) ;
	extern int* p_port ;
	



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
/*	printf("The source IP address    : %s\n" ,inet_ntoa(ip->ip_src))  ; 
	printf("The dest IP address 	 : %s\n", inet_ntoa(ip->ip_dst)) ;
	printf("The source MAC address:	 : %2x:%2x:%2x:%2x:%2x:%2x\n",
			ethernet->ether_shost[0],
	       		ethernet->ether_shost[1],
			ethernet->ether_shost[2],
			ethernet->ether_shost[3],
			ethernet->ether_shost[4],
			ethernet->ether_shost[5]) ;
//	printf("The source port		 : %d\n", src_port ) ; 
//	printf("Thee destination port  	 : %d\n", des_port) ; 
	printf(" The TCP SEQ number	 : %d\n" , tcp->th_seq) ;
	//follow_journal(p_port) ;*/
	check_tcp(tcp) ; 
	check_arp() ; 
		return  ;



}


void check_tcp(struct sniff_tcp *tcp){
	


	if(tcp->th_flags == TH_SYN){ 
	syn_number++ ;

	printf("\n\n\nSYN NUMBER:  %d\n\n\n\n", *synp) ; 
	}
}	 
	



int get_port(){ 
	return *p_port ; 
}




void check_arp(){ 
 	const char *pattern = "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}";
	FILE *fp ; 
	char line[256] ;
       	int number = 0  ;
	int *np  = &number  ;  
	int  i = 0 ;
	fp = fopen("/proc/net/arp","r") ;
       	regex_t regex ; 
	regmatch_t match ; 
 	int start ; 
	int end ; 
	int len ; 

	if (fp==NULL){
		printf("No file found at /proc/net/arp" ) ; 
	}
	else{
		while(fgets(line,sizeof(line),fp)){
		number++ ; 	 
		}
		
	}
	rewind(fp) ; 
	char devices[*np][256] ; 
	while(fgets(line,sizeof(line),fp)){
  	       strcpy(devices[i],line) ;
	
	}

 

	

	if(regcomp(&regex,pattern, REG_EXTENDED)!= 0){
		fprintf(stderr,"FAILED TO COMPILE REGEX") ; 
		return ; 
		}
		
		rewind(fp) ; 
		
	while(fgets(line, sizeof(line),fp)){
			
	if(regexec(&regex,line,1,&match,0)==0){
		 start = match.rm_so ;
		 end = match.rm_eo ; 
		 len = end - start ; 
	
		strncpy(devices[i], line + match.rm_so , len ) ;
		devices[i][len]='\0' ; 
		i++ ; 
		
	
//		printf("\n %d Match found : %s\n",i,  devices[i-1]) ; 
		} else { 
		//	printf("\nNo match found") ; 
			}	
	
		 
		}
		int length = *np ; 
		check_dupe(devices, length) ; 

	regfree(&regex) ; 
	fclose(fp) ; 
 	return ;
}

 

/*CHECKS A 2D STRING ARRAY CONTAINING MAC ADDRESSES IN ARP TABLE FOR DUPLICATES*/

void check_dupe(char devices[][256], int length){
	char* entry[256] ; 


	for(int i = 0  ; i< length  ; i++){
		int y = 0 ; 
		for(int  j = 0 ; j < length;j++){
		if(strcmp(devices[i] , devices[j])==0){
		y++ ; 
		if(y>=2){
		printf("\nfound a duplicate,  %s  :    %s", devices[i], devices[j]) ;
		y= 0 ;	
			FILE *fp ; 
			char line[256] ; 
			fp=fopen("/proc/net/arp","r") ; 
				
			while(fgets(line,sizeof(line),fp)){
				if(strstr(line , devices[i])!=NULL){
				strcat(line, "^WARNING DUPLIATE MAC IN ARP TABLE^") ; 
					write_file(line) ;  
						}

  					}
				}
			}
		}

	}
}
