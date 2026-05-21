#include <stdio.h>


#include <time.h>
#include <systemd/sd-journal.h>
#include <pcap.h>
#include "network.h" 
#include <stdlib.h>
#include <stdbool.h>

static sd_journal *j = NULL;
struct tm current_time = {0} ; 
struct tm *ctp = &current_time ; 	
struct service configuration ; 
struct service *config_p  ; 

	

void parse_filter(char* message) ;
void update_time()  ; 
void write_file(char* message); 	
void service_config() ; 
void check_bf(char *message) ; 

int count ; 
int *countp = &count;

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





/*FUNCTION BELOW IS NOT USED AT ALL*/	
char* send_message(char* message ){ 
		if(!j){
		printf("No journal file found") ; 
		return(NULL); 
		} 

	
		strcpy(config_p->port_n, "22") ; 
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
		//	printf("%.*s\n,(int)(length-8),(const char *)data+8) ;	
			} 
		}


/*TO FOLLOW JOURNAL LOGS AND UPDATE*/		
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
 			parse_filter(message) ; 
			check_bf(message) ; 
		}
	}
}






void close_journal(){
		sd_journal_close(j) ; 
		j=NULL ; 
		}



/*PARSE FILTER CHECKS FOR SERVICE CONFIGURATION STRUCT (struct service)  BEFORE WRITING TO A FILE*/

void  parse_filter(char* message ){
	service_config() ; 
	

	if(	 strstr(message, config_p->sname )





		|| strstr(message, config_p->login)
	 	|| strstr(message, config_p->failure)
		|| strstr(message, config_p->port_n)){
		
		write_file(message)  ; 
		
		}else{
			return ;  

	}
	return ; 
}



void check_bf(char* message){
	if(strstr(message, "fail")){
	count++ ; 
	}
	if(set_timer(5)&&*countp>5){
	write_file("WARNING: POTENTIAL BRUTE FORCE ATTEMPTED") ; 
	count= 0 ; 
	}
	

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



/*WRITE TO LOGS.txt A GIVEN STRING*/

void write_file(char* message ){ 
	
	update_time() ; 
	 
	FILE *fp  ; 
	fp = fopen("LOGS.txt","a") ; 
	fprintf(fp, "\n %d:%d:%d LOG: %s  \n ", ctp->tm_hour, ctp->tm_min,ctp->tm_sec,message );  
	fclose(fp) ; 
	
}





/*CONFIGURE A STRUCT TO PARSE THE VALUES OF THE CHOSEN SERVICE*/

void service_config(){

	config_p = &configuration ;

		if(get_port() == 22 ){
	
			strcpy(config_p->sname, "ssh") ; 
			strcpy(config_p->login, "login") ; 
			strcpy(config_p->failure,"fail") ;
			strcpy(config_p->port_n,"22")  ; 
		
			printf("hello the port is %d" , get_port() ) ; 
		}else{
			printf("Invalid service configuation") ; 
		
			}
		return ; 
		}
		




bool set_timer( int time){
		update_time() ; 
		if(ctp->tm_sec%time==0){
		       return(1) ;  
		}else{
			return(0) ; 
			}		
}



bool write_throttle(int seconds){
	static int last_triggered = -1 ; 
	update_time() ; 
	if(ctp->tm_sec - last_triggered>=seconds){
		last_triggered = ctp->tm_sec ; 
		return true ; 
	}
	return false ; 
}
		
