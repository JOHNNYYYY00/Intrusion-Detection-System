#include <stdio.h>
#include <systemd/sd-journal.h> 


/* Service Structs */

struct service{ 

	 char sname[64];
      	 char login[64] ;
	 char failure[64] ;	
	 char port_n[64] ; 
	
	
} ; 








/* Function Prototypes */ 

int init_journal() ;
char* send_message(char* message)  ;
void close_journal() ; 
void follow_journal(int* port) ;
void parse_filter(char* message  ) ;
void update_time() ;
void write_file() ;
void service_config() ; 


