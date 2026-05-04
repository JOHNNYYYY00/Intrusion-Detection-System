#include <stdio.h>
#include <systemd/sd-journal.h> 


int init_journal() ;
char* send_message(char* message)  ;
void close_journal() ; 
void parse_filter(char* message  , int* port) ; 
