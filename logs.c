#include <stdio.h>
#include <systemd/sd-journal.h>
#include <pcap.h>

	static sd_journal *j = NULL;
	

	


	

	int init_journal(){
		return sd_journal_open(&j , SD_JOURNAL_LOCAL_ONLY) ; 
		} 

	
		char* send_message(char* message ){ 
		if(!j){
			printf("No journal file found") ; 
			return(NULL); 
			} 


		sd_journal_next(j) ; 



		const void *data  ;
		size_t length ; 
		
		//Write MESSAGE in field for sd_journal_get_data //

		if(sd_journal_get_data(j, "MESSAGE" , &data, &length)==0){
			
		        message[0] = '\0' ; 
			strcpy(message ,(const char *)data+8) ; 
		
					
			return(message) ; 
		//	printf("%.*s\n",(int)(length-8),(const char *)data+8) ;	
			} 
		} 

		void close_journal(){
		sd_journal_close(j) ; 
		j=NULL ; 
		}
	
void  parse_filter(char* message, int* port  ){

		printf("ccheck working as should ") ; 

	char str[16] 	 ; 
	sprintf(str, "%d" ,port) ; 
	char* sub_msg = strstr(message, str) ;
		
	if(sub_msg ){
		printf("%s\n", message) ; 
	}else{
		printf("your a cock sucker") ; 

	}
	return ; 
}
