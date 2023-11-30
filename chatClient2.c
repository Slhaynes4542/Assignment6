#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include "inet.h"
#include "common.h"
#include <stdbool.h>


//open ssl includes
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Global Variables */
bool has_nickname = FALSE;      		  /* has user entered nickname? 			  */
struct sockaddr_in serv_addr;			  /* directory and chat server addresses 	  */
int				sockfd, nsockfd;					  /* listening socket 						  */
bool 			conn_dirserver;	  		 /* is client connected to directory server? */
char 			expected_common_name[MAX]; //the expected common name our chat server should have
int port;
char			s[MAX];

/* Global OpenSSL variables for the chat server */
SSL_METHOD *method; //method that will be used to connect
SSL_CTX *ctx; //method context
SSL *ssl; //the actual ssl connection IMPORTANT
X509 *cert; //the certificate we will recieve
X509 *x509; //the human readuable x509 of the cert 
char x509_string[1024];
char common_name[MAX];

struct client
{
	char readBuff[MAX]; /* Read Buffer */ 
 	char responseBuff[MAX]; /* Response/Send Buffer */
 	char *readStartptr, *readLocptr; /* Read Positional pointers */
 	char *responseStartptr, *responseLocptr; /* Response positional pointers */
	int messageToSend; /* Determines wheather or not there is a message to send, 0 or 1 (false/true) */
};


/*************************************************
* Method: HandleMessage
* Description: Handles messages received from 
			   clients
* Params: (message - message to handle)
* Return: (1 - message is handled or nickname is
		   valid )
		  (-1 - error handling message )
*************************************************/
int HandleMessage(struct client *client_info, char * message)
{
	char* parsed_message = message + 2; 			/* message from server without overhead */
	fprintf(stderr, "%s:%d In handle message, message was: %s\n", __FILE__, __LINE__, message);
	switch(message[0])
	{
		case 'n':
			has_nickname = FALSE;
			snprintf(client_info->responseBuff, MAX, "%s", parsed_message);
			break;

		case 'c':
			snprintf(client_info->responseBuff, MAX, "%s", parsed_message);
			break; 

		case 'j':
			snprintf(client_info->responseBuff, MAX, "%s", parsed_message);
			break;
			/* directory server sends list of servers to connect to */
		case 'd':
			printf("%s\n", parsed_message);
			break;
		/* received chat server ip address */
		case 'i':
			snprintf(s, MAX, "%s", parsed_message);
			char *token;
			token = strtok(s, "|");			
			serv_addr.sin_addr.s_addr	= inet_addr(token);
			token = strtok(NULL, "|");
			port = atoi(token); //FIXME
			serv_addr.sin_port = htons(port);
			token = strtok(NULL, "|");
			snprintf(expected_common_name, MAX, "%s_chatServer", token);
			break;
		/*recieved chat server port number */
		case 'p':
			/* we now have what we need to close the connection with the directory server,
			and establish a connection with the chat server */
			port = atoi(parsed_message);
			serv_addr.sin_port = htons(port);
			

			/* close connection with directory server */
			close(sockfd);
			conn_dirserver = FALSE;

			/* establish a connection with the chat server */
			ConnectToChatServer();
			
		break;
		/*Client entered an invalid chat room name, send a new one */
		case 'v':
			snprintf(client_info->responseBuff, MAX, "%s", parsed_message); //FIXME
			break;
		default:
		return -1;
		break;
	}

	return 1;

}


void ConnectToChatServer()
{
	/* Create a socket (an endpoint for communication). */
	if ((nsockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		exit(1);
	}



	/* Connect to the directory server. */
	//serv_addr.sin_addr.s_addr =  inet_addr(SERV_HOST_ADDR);

	if (connect(nsockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("client: can't connect to server");
		exit(1);
	}

	/*SSL: Preliminary SSL setup, link ssl object with directory server file descriptor */
	
	//MAY HAVE TO MALLOC SOME MEMORY
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = SSLv23_method();
	ctx = SSL_CTX_new(method);
	

	/* SSL: set up tls connection with chat server - get certificate */
	ssl = SSL_new(ctx); //create a new SSL connection state with our method context
	SSL_set_fd(ssl, nsockfd);
	if ( SSL_connect(ssl) == -1 )     /* perform the connection */ //FIX ME Bricking on this connection, chatsever5 error?
		ERR_print_errors_fp(stderr);        /* report any errors */

	
	int nval = fcntl(nsockfd, F_GETFL, 0);		//Make nsockfd non blocking
	fcntl(nsockfd, F_SETFL, nval | O_NONBLOCK);	//Make nsockfd non blocking

	/* SSL: Validate the certificate if good keep connection, otherwise close connection
	

	if valid:
	keep connection

	if invalid:
	SSL_shutdown()
	then close socket ?
	free memory
	
	*/

	cert = SSL_get_peer_certificate(ssl); //get cert from connection
	x509 = X509_get_subject_name(cert); //get x509
	X509_NAME_oneline(x509, x509_string, 1024); //get it in one line

	//go through the x509 and find where the it has CN= , this is the common name, get the common name
	for(int i = 0; i < 1020; i++){
		if(x509_string[i] == 'C' && x509_string[i+1] == 'N' && x509_string[i+2] == '='){
			snprintf(common_name, MAX, "%s", x509_string+i+3);
			break;
		}
	}

	//DEBUG
	fprintf(stderr, "%s:%d Chat server common name is: %s\n Expected: %s\n", __FILE__, __LINE__, common_name, expected_common_name);
	if(0 != strncmp(common_name, expected_common_name, MAX)){
				fprintf(stderr, "%s:%d Common name is not correct, bad cert\n", __FILE__, __LINE__);
				close(nsockfd);
	}



}
int main()
{	
	fd_set			readset;					/* set of file descriptors (sockets) available to read  */
	fd_set			writeset;					/* set of file descriptors (sockets) ready to write     */
	struct sockaddr_in dirserv_addr;		    /* directory server address 					        */
	int				nread;					    /* number of characters 	  					        */
	int 			nwrite;


	struct client *client_info = malloc(sizeof(struct client));
	#pragma region Intializing Buffers and Pointers
	client_info->readStartptr = client_info->readBuff;
	client_info->readLocptr = client_info->readStartptr;
	client_info->responseStartptr = client_info->responseBuff;
	client_info->responseLocptr = client_info->responseStartptr; //FIXME
	#pragma endregion


	/* Set up the address of the directory server to be contacted. */
	memset((char *) &dirserv_addr, 0, sizeof(dirserv_addr));
	dirserv_addr.sin_family			= AF_INET;
	dirserv_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);
	dirserv_addr.sin_port			= htons(SERV_TCP_PORT);		

	/* Set up the address of the chat server to be contacted. IP address and port number will be retrieved from the directory server */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family			= AF_INET;	

	/* Create a socket (an endpoint for communication). */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		exit(1);
	}


	/* Connect to the directory server. */
	if (connect(sockfd, (struct sockaddr *) &dirserv_addr, sizeof(dirserv_addr)) < 0) {
		perror("client: can't connect to server");
		exit(1);
	}
	
	/*SSL: Preliminary SSL setup, link ssl object with directory server file descriptor */
	SSL_METHOD *directory_method;
	SSL_CTX *directory_ctx;
	OpenSSL_add_all_algorithms();       /* Load cryptos, et.al. */
	SSL_load_error_strings();        /* Load/register error msg */
	directory_method = SSLv23_method(); /* Create new client-method */ //FIXME dont know if this method will
	directory_ctx = SSL_CTX_new(directory_method);            /* Create new context */

	/* SSL: set up tls connection with directory server - get certificate */
	SSL *directory_ssl = SSL_new(directory_ctx);
	SSL_set_fd(directory_ssl, sockfd);
	if ( SSL_connect(directory_ssl) == -1 )     /* perform the connection */
		ERR_print_errors_fp(stderr);

int val = fcntl(sockfd, F_GETFL, 0);		//Make sockfd non blocking
	fcntl(sockfd, F_SETFL, val | O_NONBLOCK);	//Make sockfd non blocking

	/* SSL: Validate the certificate if good keep connection, otherwise close connection */

	char line[1024];
	X509 *directory_cert = SSL_get_peer_certificate (directory_ssl);
	X509 *directory_x509 = X509_get_subject_name(directory_cert);    /* Get subject */
	X509_NAME_oneline(directory_x509, line, 1024); /* Convert it */

	char directory_commonName[MAX];
	for(int i = 0; i < 1020; i++){
		if(line[i] == 'C' && line[i+1] == 'N' && line[i+2] == '='){
			snprintf(directory_commonName, MAX, "%s", line+i+3);
			break;
		}
	}

	fprintf(stderr, "%s:%d server common name is: %s\n Expected: directory_server \n", __FILE__, __LINE__, directory_commonName);
	if(0 != strncmp(directory_commonName, "directory_server", MAX)){
		close(sockfd);
		exit(1);
	}
	



	/* Once connection is established, immediately send a message to the directory server indicating this is a chat client*/
		
		conn_dirserver = TRUE;
		fprintf(stderr, "%s:%d Connection Established!\n", __FILE__, __LINE__);
		snprintf(client_info->responseBuff, MAX, "c,");
		SSL_write(directory_ssl, client_info->responseBuff, MAX); //FIXME may have to do a little mutli part check here to make sure we write evrything
		//write(sockfd, client_info->responseBuff, MAX);
	
	/* SSL: read from directory server */ 
		fprintf(stderr, "%s:%d Waiting for directory to send back chat servers\n", __FILE__, __LINE__);

		int bytes = -1;
		do{
		FD_SET(sockfd, &readset);
		select(sockfd+1, &readset, NULL, NULL, NULL);
		bytes = SSL_read(directory_ssl, client_info->readBuff, MAX);
		}while(((client_info->readBuff)[0] != 'd') );

		fprintf(stderr, "%s:%d Recieved chat servers, message was %d bytes\n", __FILE__, __LINE__, bytes);
			/* 1.call handle message and get all available chat servers */
		HandleMessage(client_info, client_info->readBuff);
			
			/* get user input */
		if (1 == scanf(" %99[^\n]", client_info->responseBuff)) {

					snprintf(s, MAX, "r,%s", client_info->responseBuff);
					SSL_write(directory_ssl, s, MAX);
		}

			/*write to directory server what chat server to join*/
			bytes = -1;
		do{
		FD_SET(sockfd, &readset);
			select(sockfd+1, &readset, NULL, NULL, NULL);
			bytes = SSL_read(directory_ssl, client_info->readBuff, MAX);
		}while(((client_info->readBuff)[0] != 'i'));
		fprintf(stderr, "%s:%d Recieved chat server info, message was %d bytes\n", __FILE__, __LINE__, bytes);
			/*read directory server message which will contain the ip,port, and common name of chat server*/
			HandleMessage(client_info, client_info->readBuff);
			/*disconnect from directory server and connect chat server*/

			ConnectToChatServer();

	
	for(;;) {

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);
		FD_SET(sockfd, &writeset);
		

		if (select(sockfd+1, &readset, &writeset, NULL, NULL) > 0)
		{
			/* Check whether there's user input to read */
			if (FD_ISSET(STDIN_FILENO, &readset))
			 {

				if (1 == scanf(" %99[^\n]", client_info->responseBuff)) 
				{
					/* if connected to directory server, specify chat room to join */
					if(conn_dirserver)
					{
						snprintf(client_info->readBuff, MAX, "r,%s", client_info->responseBuff);

					}
					/*if haven't specified a nickname, specify nickname*/
					else if(!has_nickname)
					{
						snprintf(client_info->readBuff, MAX,"n,%s", client_info->responseBuff);	
						has_nickname = TRUE;
					}
					/*else, send a chat*/
					else
					{
						snprintf(client_info->readBuff, MAX, "c,%s\n", client_info->responseBuff);
						
					}

										
				} 
				else
				{
					printf("Error reading or parsing user input\n");
				}
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) 
			{
				
				//if ((nread = read(sockfd, client_info->readLocptr, MAX - (client_info->readLocptr - client_info->readBuff))) <= 0) 
				if((nread = SSL_read(ssl, client_info->readLocptr, MAX - (client_info->readLocptr - client_info->readBuff)))  <= 0)
				{
					printf("Error reading from server\n");
					exit(0);
				} 
				else 
				{
					/* handle response from server */
					 HandleMessage(client_info, client_info->readBuff);
					/*print response from server */
					fprintf(stderr, "\n%s\n", client_info->responseBuff);
				}
			}

			if(FD_ISSET(sockfd, &writeset)){
				/* Send the user's message to the server */
				//if((nwrite = write(sockfd, client_info->responseStartptr, client_info->responseLocptr - client_info->responseStartptr)) >= 0)
				if((nwrite = SSL_write(sockfd, client_info->responseStartptr, client_info->responseLocptr - client_info->responseStartptr)) >= 0)
				{
					client_info->responseLocptr -= nwrite; //Move back the amount of bytes we wrote from pointer, removing them from buffer
					int bytesleft = client_info->responseLocptr - client_info->responseStartptr;
					for(int i = 0; i < bytesleft; i++){
						client_info->responseStartptr[i] = client_info->responseStartptr[nwrite + i];
					} //iterate through the bytes left in buffer to move them back the same amount of bytes we've written (nwrite)
					client_info->messageToSend = FALSE;
				}

			}
		}
	}
	free(client_info);
	close(sockfd);
}

