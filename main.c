#include <stdio.h>
#include <sys/socket.h>
#include "network.h"
#include <pcap.h>
#include <string.h>
#include <systemd/sd-journal.h>
#include "logs.h"
#include "interface.h"
#include <stdlib.h>
#include <pthread.h> 

int port  ; 
int *p_port  ; 


	typedef struct {
		pcap_t *handle ; 
	}pcap_args  ;

	typedef struct{ 
		int* port ; 
	}journal_args ; 

void *pcap_thread(void *args){
	pcap_args *pargs = (pcap_args *)args ; 
	pcap_loop(pargs->handle , -1, packet_handler,NULL) ; 
	return NULL ; 
}


void *journal_thread(void *args){ 
	journal_args *jargs = (journal_args*)args ; 
	follow_journal(jargs->port) ;
	return NULL ; 
}



int main(int argc, char *argv[]){

	char *dev ; 
	char errbuf[PCAP_ERRBUF_SIZE] ;  
	dev = pcap_lookupdev(errbuf) ; 
	char *ICMP = "icmp" ; 
	struct bpf_program fp ; 
	char *filter_exp = malloc(100) ; 
	bpf_u_int32 mask ; 
	bpf_u_int32 net   ; 
	struct pcap_pkthdr header ; 
	const u_char *packet ; 
	p_port = &port ;	
	init_journal() ;

		
	interface_menu(p_port, filter_exp) ; 
	printf("%s    \n", filter_exp)  ;

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
//	check_arp() ;
	
	pthread_t pcap_tid ; 
	pthread_t journal_tid ; 

	pcap_args pargs ; 
	pargs.handle = handle ; 

	journal_args jargs ; 
	jargs.port = p_port ; 


	pthread_create(&journal_tid ,NULL ,journal_thread, &jargs) ; 
	pthread_create(&pcap_tid, NULL ,pcap_thread, &pargs) ; 

	pthread_join(journal_tid, NULL ) ;
	pthread_join(pcap_tid, NULL) ;



		
	pcap_loop(handle , -1 , packet_handler,NULL) ; 
	follow_journal(p_port) ; 

	close_journal();
	pcap_close(handle) ;	


	return 0 ; 
}
