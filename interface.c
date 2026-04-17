#include <stdio.h>
#include <string.h>

void set_expression(int* port, char* filter_exp) ;

int interface_menu(int* port , char* filter_exp ){


	while(1){
		printf("following port modes are accepted\n") ; 
		printf("Port 80\n") ;
		printf("Port 22\n") ; 
		printf("Port 443\n") ; 
		printf("Port 53\n")  ; 
		 
		scanf("%d", port) ; 
	switch(*port){
	case 80:

	set_expression(port, filter_exp) ; 	
	printf("Scanning port 80\n") ;
	return 0  ; 
       	break  ;
		
	case 22:
	set_expression(port , filter_exp) ;
	printf("Scanning port 22\n") ; 
	return 0 ; 
	break ; 
	case 443: 
	set_expression(port ,filter_exp) ; 
	printf("Scanning port 443\n") ; 
	return 0 ; 
	break ; 
	case 53:
	set_expression(port, filter_exp) ; 
	printf("Scanning port 54\n") ; 
	return 0 ; 
	break ; 
	}
		
	} 
	return(1) ; 
}
    

void set_expression(int* port, char* filter_exp){


	char temp[100] ; 
	sprintf(temp ,"%d" , *port) ;
       	
	filter_exp[0] = '\0' ; 
	strcpy(filter_exp, "port ") ; 
       	strcat(filter_exp ,temp ) ; 	

	
}

