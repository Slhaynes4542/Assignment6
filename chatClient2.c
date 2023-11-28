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

/* Global Variables */
bool has_nickname = FALSE;      		  /* has user entered nickname? 			  */
struct sockaddr_in serv_addr;			  /* directory and chat server addresses 	  */
int				sockfd, nsockfd;					  /* listening socket 						  */
bool 			conn_dirserver;	  		 /* is client connected to directory server? */
int port;

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
int HandleMessage(char * message)
{
	char* parsed_message = message + 2; 			/* message from server without overhead */

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
		case 'd':
			snprintf(client_info->responseBuff, MAX, "%s", parsed_message);
			break;
		/* received chat server ip address */
		case 'i':
			serv_addr.sin_addr.s_addr	= inet_addr(parsed_message);
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
			snprintf(response, MAX, "%s", parsed_message);
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

	int nval = fcntl(nsockfd, F_GETFL, 0);		//Make nsockfd non blocking
	fcntl(nsockfd, F_SETFL, nval | O_NONBLOCK);	//Make nsockfd non blocking


	/* Connect to the directory server. */
	serv_addr.sin_addr.s_addr =  inet_addr(SERV_HOST_ADDR);

	if (connect(nsockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("client: can't connect to server");
		exit(1);
	}

	/*SSL: Preliminary SSL setup, link ssl object with directory server file descriptor */

	

	/* SSL: set up tls connection with chat server - get certificate */
				

	/* SSL: Validate the certificate if good keep connection, otherwise close connection
	
	if valid:
	keep connection

	if invalid:
	SSL_shutdown()
	then close socket ?
	free memory
	
	*/

}
int main()
{	
	fd_set			readset;					/* set of file descriptors (sockets) available to read  */
	fd_set			writeset;					/* set of file descriptors (sockets) ready to write     */
	struct sockaddr_in dirserv_addr;		    /* directory server address 					        */
	int				nread;					    /* number of characters 	  					        */

	struct client *client_info = malloc(sizeof(struct client));
	#pragma region Intializing Buffers and Pointers
	client_info->readStartptr = client_info->readBuff;
	client_info->readLocptr = client_info->readStartptr;
	client_info->responseStartptr = client_info->responseBuff;
	client_info->responseStartLoc = client_info->responseStartptr;
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

	int val = fcntl(sockfd, F_GETFL, 0);		//Make sockfd non blocking
	fcntl(sockfd, F_SETFL, val | O_NONBLOCK);	//Make sockfd non blocking


	/* Connect to the directory server. */
	if (connect(sockfd, (struct sockaddr *) &dirserv_addr, sizeof(dirserv_addr)) < 0) {
		perror("client: can't connect to server");
		exit(1);
	}
	
	/*SSL: Preliminary SSL setup, link ssl object with directory server file descriptor */

	

	/* SSL: set up tls connection with directory server - get certificate */
				

	/* SSL: Validate the certificate if good keep connection, otherwise close connection
	
	if valid:
	keep connection

	if invalid:
	SSL_shutdown()
	then close socket ?
	free memory
	
	*/

	/* Once connection is established, immediately send a message to the directory server indicating this is a chat client*/
	else
	{
		conn_dirserver = TRUE;
		fprintf(stderr, "%s:%d Connection Established!\n", __FILE__, __LINE__);
		snprintf(client_info->responseBuff, MAX, "c");
		write(sockfd, client_info->responseBuff, MAX);
	}

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
				if ((nread = read(sockfd, client_info->readLocptr, MAX - (client_info->readLocptr - client_info->readBuff))) <= 0) 
				{
					printf("Error reading from server\n");
					exit(0);
				} 
				else 
				{
					/* handle response from server */
					 HandleMessage(client_info->readBuff);
					/*print response from server */
					fprintf(stderr, "\n%s\n", client_info->responseBuff);
				}
			}

			if(FD_ISSET(sockfd, &writeset)){
				/* Send the user's message to the server */
				if((nwrite = write(sockfd, client_info->responseStartptr, client_info->responseLocptr - client_info->responseStartptr)) >= 0){
					client_info->responseLocptr -= nwrite; //Move back the amount of bytes we wrote from pointer, removing them from buffer
					bytesleft = client_info->responseLocptr - client_info->responseStartptr;
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

