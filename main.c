#include <stdio.h>
#include <sys/socket.h>
#include "network.h"
#include <pcap.h>
#include <string.h>
#include <systemd/sd-journal.h>
#include "logs.h"
int main(int argc, char *argv[]){

	char *dev ; 
	char errbuf[PCAP_ERRBUF_SIZE] ;  
	dev = pcap_lookupdev(errbuf) ; 
	char *ICMP = "icmp" ; 
	struct bpf_program fp ; 
	char filter_exp[]="port 22" ; 
	bpf_u_int32 mask ; 
	bpf_u_int32 net   ; 
	struct pcap_pkthdr header ; 
	const u_char *packet ; 

	init_journal() ;


	printf("Device targeted: %s\n",dev) ; 
	
	pcap_t *handle ; 

	handle = pcap_open_live(dev , BUFSIZ, 0 , 1000, errbuf) ; 
	if(handle ==NULL){

	fprintf(stderr , "Couldn't open device %s: %s\n", dev , errbuf) ; 	
	return(2)  ; 
	} 

	if( pcap_datalink(handle) != DLT_EN10MB) { 
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not suported \n" , dev) ;
		return(2) ; 
	} 
  	
	
	if(pcap_compile(handle, &fp,filter_exp,1,net)==-1){
		fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle)) ;
		return(2) ; 
	}

	


	pcap_loop(handle , -1 , packet_handler ,NULL) ; 

	

	close_journal();
	pcap_close(handle) ;	


	return 0 ; 
}
