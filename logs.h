#include <stdio.h>
#include <systemd/sd-journal.h> 


int init_journal() ;
char* send_message(char* message)  ;
void close_journal() ; 
void follow_journal(int* port) ;
void parse_filter(char* message  , int* port) ;
void update_time() ;
void write_file() ;
