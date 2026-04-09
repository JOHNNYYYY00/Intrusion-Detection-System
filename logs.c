#include <stdio.h>
#include <systemd/sd-journal.h>


	static sd_journal *j = NULL;


	int init_journal(){
		return sd_journal_open(&j , SD_JOURNAL_LOCAL_ONLY) ; 
		} 

	
		void send_message(){ 
		if(!j){
			printf("No journal file found") ; 
			return ; 
			} 


		sd_journal_next(j) ; 



		const void *data  ;
		size_t length ; 

		if(sd_journal_get_data(j, "_KERNEL_DEVICE" , &data, &length)==0){
		printf("%s\n", (const char*)data+8) ; 
			} 
		} 

		void close_journal(){
		sd_journal_close(j) ; 
		j=NULL ; 
		}
