#include <stdio.h>


#include <time.h>
#include <systemd/sd-journal.h>
#include <pcap.h>

static sd_journal *j = NULL;
struct tm current_time = {0} ; 
struct tm *ctp = &current_time ; 	


	

void parse_filter(char* message, int* port) ;
void update_time()  ; 
void write_file(); 	



int init_journal(){

	int r = sd_journal_open(&j , SD_JOURNAL_LOCAL_ONLY) ; 
	if(r<0){
	printf("failed to open journal\n") ; 
	 return r; 
	}
	
	sd_journal_add_match(j,"_SYSTEMD_UNIT=sshd.service",0) ; 
	sd_journal_seek_tail(j) ; 
	sd_journal_previous(j) ; 
	return 0 ; 


	} 





	
char* send_message(char* message ){ 
		if(!j){
		printf("No journal file found") ; 
		return(NULL); 
		} 


		sd_journal_next(j)  ; 

		const void *data  ;
		size_t length ; 
		
		//Write MESSAGE in field for sd_journal_get_data //
		

		const void *identifier_data ;
		size_t identifier_length  ; 
		if(sd_journal_get_data(j,"SYSLOG_IDENTIFIER", &identifier_data, &identifier_length)==0){
				char *identifier = (char *)identifier_data ; 

				if(strncmp(identifier,"kernel",6)==0||
						strncmp(identifier,"ACPI",4)==0||
					strncmp(identifier, "efi",3)==0||
					strncmp(identifier,"e820",4)==0){
				return NULL ;
				}
				}



		if(sd_journal_get_data(j, "MESSAGE" , &data, &length)==0){
			
		        message[0] = '\0' ; 
			strcpy(message ,(const char *)data+8) ; 
		
					
			return(message) ; 
		//	printf("%.*s\n",(int)(length-8),(const char *)data+8) ;	
			} 
		}
		
void follow_journal(int* port){
	const void *data ;
	size_t length ; 
	char message[512] ; 
	
	while(1){
	int r = sd_journal_wait(j,1000000) ;
	if(r<0){
	 printf("Journal error: %s\n", strerror(-r)) ;
	 break ; 
	}

	while(sd_journal_next(j) > 0) {
	 if(sd_journal_get_data(j,"MESSAGE",&data,&length) < 0)
	  continue; 

	const char *msg = (const char *)data+8 ; 
	int msg_len = (int)(length - 8) ;

	uint64_t usec ; 
	sd_journal_get_realtime_usec(j,&usec) ; 
	time_t t = usec / 1000000 ;
	char timebuf[64];
	strftime(timebuf,sizeof(timebuf),"%b %d %H: %M: %S" , localtime(&t)) ; 

	printf("%s %.*s\n",timebuf,msg_len,msg) ; 
	
	snprintf(message, sizeof(message), "%.*s", msg_len,msg) ; 
 	parse_filter(message,port) ; 
	}
}
}






void close_journal(){
		sd_journal_close(j) ; 
		j=NULL ; 
		}




void  parse_filter(char* message, int* port  ){

	
	char str[16] 	 ; 
	sprintf(str, "%d" ,*port) ; 
	char* sub_msg = strstr(message, str) ;
		
	if(sub_msg || strstr(message, "sshd")|| strstr(message, "ssh") ){
		printf("[MATCH]%s\n", message) ; 
		printf("\n CHECK CHECK CHECK DIS HOE\n") ; 
		
		write_file()  ; 
	}else{
		return ;  

	}
	return ; 
}






void update_time(){
	if(ctp!=NULL){

	   time_t now  = time(NULL) ; 
	   ctp   =  localtime(&now) ; 
	return ;
 
	}else{
	   printf("Couldnt get time") ;
	}
        return; 
}




void write_file( ){ 
	
	update_time() ; 
	 
	FILE *fp  ; 
	fp = fopen("LOGS.txt","a") ; 
	fprintf(fp, "\n the year is: %d ", ctp->tm_hour);  
	fclose(fp) ; 
	
}













