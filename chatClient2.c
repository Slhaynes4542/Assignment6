#include <stdio.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "inet.h"
#include "common.h"
#include <stdbool.h>

/* Global Variables */
char response[MAX];						  /* response from server 	 	 			  */
bool has_nickname = FALSE;      		  /* has user entered nickname? 			  */
struct sockaddr_in serv_addr;			  /* directory and chat server addresses 	  */
int				sockfd, nsockfd;					  /* listening socket 						  */
bool 			conn_dirserver;	  		 /* is client connected to directory server? */
int port;

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
			snprintf(response, MAX, "%s", parsed_message);
			break;

		case 'c':
			snprintf(response, MAX, "%s", parsed_message);
			break; 

		case 'j':
			snprintf(response, MAX, "%s", parsed_message);
			break;
		case 'd':
			snprintf(response, MAX, "%s", parsed_message);
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
	char s[MAX] = {'\0'};						/* message 										        */
	char message[MAX] = {'\0'};					/* message 										    	*/
	fd_set			readset;					/* set of file descriptors (sockets) available to read  */
	struct sockaddr_in dirserv_addr;		    /* directory server address 					        */
	int				nread;					    /* number of characters 	  					        */

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
		snprintf(response, MAX, "c");
		write(sockfd, response, MAX);
	}

	for(;;) {

		FD_ZERO(&readset);
		FD_SET(STDIN_FILENO, &readset);
		FD_SET(sockfd, &readset);

		if (select(sockfd+1, &readset, NULL, NULL, NULL) > 0)
		{
			/* Check whether there's user input to read */
			if (FD_ISSET(STDIN_FILENO, &readset))
			 {

				if (1 == scanf(" %99[^\n]", s)) 
				{
					/* if connected to directory server, specify chat room to join */
					if(conn_dirserver)
					{
						snprintf(message, MAX, "r,%s", s);

					}
					/*if haven't specified a nickname, specify nickname*/
					else if(!has_nickname)
					{
						snprintf(message, MAX,"n,%s", s);	
						has_nickname = TRUE;
					}
					/*else, send a chat*/
					else
					{
						snprintf(message, MAX, "c,%s\n", s);
					}

					/* Send the user's message to the server */
					write(sockfd, message, MAX);
				} 
				else
				{
					printf("Error reading or parsing user input\n");
				}
			}

			/* Check whether there's a message from the server to read */
			if (FD_ISSET(sockfd, &readset)) 
			{
				if ((nread = read(sockfd, s, MAX)) <= 0) 
				{
					printf("Error reading from server\n");
					exit(0);
				} 
				else 
				{
					/* handle response from server */
					 HandleMessage(s);
					/*print response from server */
					fprintf(stderr, "\n%s\n", response);
				}
			}
		}
	}
	close(sockfd);
}

