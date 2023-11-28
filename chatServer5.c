#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include "inet.h"
#include "common.h"
#include <stddef.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <stdbool.h>

/* global variables */
char 				response[MAX];					 /* response to send to clients    						*/
char 				dir_response[MAX];				 /* response to send to directory Server 				*/
char 				ip_address[INET_ADDRSTRLEN];	 /* ip address for this server 							*/
/*Client Data structure (linked list)*/
	struct client_data 
	{
		int client_fd;
		char* client_name; 
		char write[MAX], read[MAX];
		char *r_ptr, *w_ptr;
		LIST_ENTRY(client_data) entries;  /* list */
		bool writeable; 				  /* is there something to write to this client? */
	};

/*Directory Server read and write buffer */
	struct directory_server 
	{
		int dir_sockfd; 
		char write[MAX], read[MAX];    /* buffers for writing room name and port number to directory server; buffer to read from directory server*/
		char *r_ptr, *w_ptr;
	};

	LIST_HEAD(listhead, client_data); 

/*************************************************
* Method: HandleMessage
* Description: Handles messages received from 
			   clients
* Params: (message - message to handle)
* 		  (c_data - client data)
*		  (head - head of the client list )
* Return: (1 - message is handled or nickname is
		   valid )
		  (0 - invalid nickname )
		  (-1 - error handling message )
*************************************************/

int HandleMessage(char * message, struct client_data* c_data, struct listhead head)
{
	char* parsed_message = message + 2; 			/* user message with no overhead      */
	struct client_data * cp;						/* pointer for traversing client data */
	bool	unique_nickname = TRUE;			   		/* is the nickname specified unique?  */


	switch(message[0])
	{
		/*if first character is an 'n', process nickname */ 
		case 'n':
			/* process */
			LIST_FOREACH(cp, &head, entries)
			{
				/* check for duplicate nicknames, set flag */
				if(strcmp(cp->client_name, parsed_message) == 0 )
				{
					unique_nickname = FALSE;
				}
			}

			/* if nickname is unique, add to client record and generate response */
			if(unique_nickname)
			{
					snprintf(c_data->client_name, MAX, "%s", parsed_message);

					/*generate response */
					snprintf(response, MAX, "j,%s has joined the chat.", parsed_message);			
					return 1;
			}
			else
			{
				/*generate response */
				snprintf(response, MAX, "n,Nickname already exists. Please enter unique nickname: ");
				return 0;
			}
		break;

		/*if first character is a 'c', process chat */
		case 'c':
			/*generate response */
			snprintf(response, MAX, "c,%s : %s", c_data->client_name, parsed_message);
			return 1;
		break;
		/*if first character is a 'd',chat room successful */
		case 'd':
			fprintf(stderr, "Chat Room opened!\n", __FILE__, __LINE__);
			return 1;
			break;
		
		/*if first character is a 'o', chat room name is invalid, exit */
		case 'e': 
			fprintf(stderr, "Unable to open chat room. Chat room name already exists.\n");
			exit(0);

		/*otherwise, error reading message */
		default:
			fprintf(stderr, "%s:%d Error reading from client\n", __FILE__, __LINE__);
			return -1; 
		break;

	}


}



int main(int argc, char **argv)
{
	int				sockfd, new_sockfd,			 		/* listening socket and new socket file descriptor		*/
					dir_sockfd;
	unsigned int	clilen;								/* client length 										*/
	struct sockaddr_in cli_addr, serv_addr;				/* socket, client, and server addresses				    */
	char				s[MAX];
	fd_set 				readset;						/* set of file descriptors (sockets) available to read  */
	fd_set				writeset;						/* set of file descriptors (sockets) available to write z*/
	int 				max_fd = 0;						/* maximum file descriptor in readset 					*/
	int j;											
	struct listhead head;								/* head of linked list containing client data			*/
	struct client_data *c_ptr; 		 					/* pointers to client data 								*/
	struct client_data *np;								/* pointer used for traversing list         		    */
	struct client_data *np2; 							/* pointer used for traversing list   					*/	
	int client_count = 0; 								/* number of clients connected to the server 			*/
	int handle_ret;										/* return value for HandleMessage() 					*/
	int nread;										    /* stores return value of read()						*/
	int wb_space;										/* avaiable write buffer space							*/
	int nwritten;										/* number of bytes written								*/
	char 				room_name[MAX];					/* chat room name 										*/
	int 				port_number; 					/* chat server port number 						    	*/
	struct directory_server dir_serv;					/* structure representing the directory server */

/*********************************************************************************
* 		Assignment 3.5 Code : Feature 1 - Directory and Chat Server Interaction 
/*********************************************************************************/
	/* get command line arguments */
	if(argc < 3){
		perror("chat server: missing arguments");
		exit(0);
	}
	else{
		snprintf(room_name, MAX, argv[1]);
		port_number = atoi(argv[2]);
		
	}

	/* Set up the address of the Directory Server to be contacted. */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family			= AF_INET;
	serv_addr.sin_addr.s_addr	= inet_addr(SERV_HOST_ADDR);
	serv_addr.sin_port			= htons(SERV_TCP_PORT);

	/* Create a socket (an endpoint for communicating with the Directory Server)*/
	if ((dir_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("chat server: can't open stream socket");
		exit(1);
	}

	
	/* Connect to the Directory Server. */
	if (connect(dir_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("chat server: can't connect to server");
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

	else
	{
		//set socket as a non-blocking socket
		if(fcntl(dir_sockfd, F_SETFL, O_NONBLOCK) < 0)
		{
			perror("Error setting non-blocking socket.");
		}

		fprintf(stderr, "%s:%d Connection Established!\n", __FILE__, __LINE__);
		
		/*set up directory server struct */
		dir_serv.dir_sockfd = dir_sockfd;
		dir_serv.r_ptr = &(dir_serv.read[0]);


		/* send room name to directory server */
		//snprintf(dir_serv.room_to, MAX, "n,%s", room_name);
		snprintf(dir_response, MAX, "n,%s", room_name);
		write(dir_sockfd, dir_response, MAX);				// HW6: how should we handle these two write()?

		/* send port number to directory server */
		//snprintf(dir_serv.port_num_to, MAX, "p,%d", port_number);
		snprintf(dir_response, MAX, "p,%d", port_number);
		write(dir_sockfd, dir_response, MAX);

		//FD_SET(dir_serv.dir_sockfd, &writeset);

	}

	/* initialize linked list */
	LIST_INIT(&head);

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		exit(1);
	}

	/*1. SSL: Initialize SSL related objects Load in the certificate */

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port		= htons(port_number);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
	{
		perror("server: can't bind local address");
		exit(1);
	}

	/* set max file descriptor */
	max_fd = sockfd;

	/* specify that the listening socket is listening for 5 connections */
	listen(sockfd, 5);

	for (;;)
	{

		fflush(stdout);
		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_SET(0, &readset);
		FD_SET(sockfd, &readset);
		FD_SET(dir_sockfd, &readset);
		

		/* re-add all socket descriptors to readset */
     	LIST_FOREACH(np, &head, entries){
			FD_SET(np->client_fd, &readset);
			FD_SET(np->client_fd, &writeset);
			
		} 
	
		/* see if any descriptors are ready to be read, wait forever. */
		if ((j=select(max_fd+1, &readset, &writeset, NULL, NULL)) > 0) 
		{
			 if(FD_ISSET(dir_sockfd, &readset))
			{
						if ((nread = read(dir_serv.dir_sockfd, dir_serv.r_ptr, &(dir_serv.read[MAX]) - dir_serv.r_ptr)) <= 0) 
						{	
							/* error checking */
							if(errno != EWOULDBLOCK)
							 { 
								perror("read error on socket"); 
							 }
							else if( nread == 0)
							{
								fprintf(stderr, "%s:%d: EOF on socket\n", __FILE__, __LINE__);
							}
							else
							{
								perror("directory server closed.");
								exit(0);
							}
							
						}
						/* if n is greater than 0, we've read in n bytes. Update read_ptr. */
						else if(nread > 0){
							dir_serv.r_ptr += nread; 
						}
						/*if the r_ptr is equal to the the MAX address of the read buffer, we have the entire message. Proceed with handling message.*/
						if(dir_serv.r_ptr == &(dir_serv.read[MAX]))
						{
							/* handle message */
							handle_ret = HandleMessage(dir_serv.read, NULL, head);

							/* reset r_ptr and clear read buffer */ 
							memset(dir_serv.read, 0, MAX);
							dir_serv.r_ptr = &(dir_serv.read);
						}	
			}

			if(FD_ISSET(sockfd,&readset)) 
			{
			/* Accept a new connection request */
					clilen = sizeof(cli_addr);
					new_sockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
					if (new_sockfd < 0) {
						perror("server: accept error");
						exit(1);
					}
					//set socket as a non-blocking socket
					if(fcntl(new_sockfd, F_SETFL, O_NONBLOCK) < 0){
						perror("Error setting non-blocking socket.");
					}

					printf("Client connected!");

			/*SSL: Create SSL session state based on context & call SSL_accept */

			/*SSL: Change read and writes to SSL_read() SSL_write()*/					

			/*store client data in client data structure */
					struct client_data *new_client = (struct client_data *)malloc(sizeof(struct client_data));
					new_client->client_name = (char*)malloc(MAX);
					new_client->client_fd = new_sockfd;
					new_client->r_ptr = &(new_client->read[0]);
					new_client->w_ptr = &(new_client->write);
					fprintf(stderr, "\nclient fd: %d\n", new_client->client_fd);
					/* if client is the first client, make this client the head of the linked list and announce event; else, add client to end of list */
					if(client_count == 0 )
					{
						LIST_INSERT_HEAD(&head, new_client, entries); 
						c_ptr = new_client;
						snprintf(response, MAX, "j,You are the first to join the chat!\nPlease Enter a nickname:");
						snprintf(new_client->write, MAX, response);
						new_client->writeable = TRUE;
					}
					else
					{
						LIST_INSERT_AFTER(c_ptr, new_client, entries);
						c_ptr = new_client;
						snprintf(response, MAX, "j,Please enter nickname: ");
						strncpy(new_client->write, response, MAX);
						new_client->writeable = TRUE;

					}
					
					/*increment client count */
					client_count++;
					/*update max file descriptor */
					if(max_fd < new_sockfd)
					{
						 max_fd = new_sockfd;
					}	
					
					/*Prompt user to specify nickname */
					
					//write(new_sockfd, response, MAX);
			}
			else
			{
				/*else, read from a client socket */
				LIST_FOREACH(np, &head, entries)
				{
					
					if(FD_ISSET(np->client_fd, &readset))
					{
					
						/*if read returns 0 or less, client has disconnected; Else, read message from client */
						if ((nread = read(np->client_fd, np->r_ptr, &(np->read[MAX]) - np->r_ptr)) <= 0) 
						{	
							/* error checking */
							if(errno != EWOULDBLOCK)
							 { 
								perror("read error on socket"); 
							 }
							else if( nread == 0)
							{
								fprintf(stderr, "%s:%d: EOF on socket\n", __FILE__, __LINE__);
							}
							/* Remove client from list */
							close(np->client_fd);
							LIST_REMOVE(np, entries);
							free(np->client_name);
							free(np);				
							client_count--;
							/* set c_ptr to the end of the list */
							LIST_FOREACH(np2, &head, entries)
							{
								if(LIST_NEXT(np2, entries) == NULL)
								{
									c_ptr = np2;
								}
							}	
							
						}
						/* if n is greater than 0, we've read in n bytes. Update read_ptr. */
						else if(nread > 0){
							np->r_ptr += nread; 
						}
						/*if the r_ptr is equal to the the MAX address of the read buffer, we have the entire message. Proceed with handling message.*/
						if(np->r_ptr == &(np->read[MAX]))
						{
							/* handle message */
							handle_ret = HandleMessage(np->read, np, head);

							/* reset r_ptr and clear read buffer */ 
							memset(np->read, 0, MAX);
							np->r_ptr = &(np->read);
							
							/* If HandleMessage() return 1, then broadcast message to all clients except the sender. */
							if(handle_ret == 1)
							{
								LIST_FOREACH(np2, &head, entries)
								{
									
									
										if(np2->w_ptr == &(np2->write))
										{
											strncpy(np2->write, response, MAX);
										}
									np2->writeable = TRUE;
										
								}

										//write(np2->client_fd, response, MAX);
							}
										
								}
								/* If HandleMessage() returns 0, user has entered an invalid nickname. */
							if( handle_ret == 0 )
							{
								if(np->w_ptr == &(np->write))
										{
											strncpy(np->write, response, MAX);
										}
								np->writeable = TRUE;
							}
					}
							
				}		
			}

			/* write to clients */
			LIST_FOREACH(np2, &head, entries)
			{
				/* if fd is in writeset, then process write */
				//int val = ((wb_space = &(np2->write[MAX]) - np2->w_ptr) > 0);
				if(np2->writeable && FD_ISSET( np2->client_fd, &writeset) && ((wb_space = &(np2->write[MAX]) - np2->w_ptr) > 0))
				{
						if((nwritten = write(np2->client_fd, np2->w_ptr, wb_space)) < 0){
							if (errno != EWOULDBLOCK) { perror("write error on socket"); }
						}
					else
					{
						/*increment write buffer pointer */
						np2->w_ptr += nwritten;
						
						/* check if entire message has been written. If so, clear write buffer, reset w_ptr, and set the writable flag to false */
						if(&(np2->write[MAX]) == np2->w_ptr){

							/* clear write buffer */
							memset(np2->write, 0, MAX);

							/* reset w_ptr */
							np2->w_ptr = &(np2->write); 

							/* set writable flag to false */
							np2->writeable = FALSE;

						}
						else{
							np2->writeable = TRUE;
						}
					}
				}
			}
		}
	}
}


