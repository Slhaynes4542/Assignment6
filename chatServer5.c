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
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

/* global variables */
char 				response[MAX];					 /* response to send to clients    						*/
char 				dir_response[MAX];				 /* response to send to directory Server 				*/
char 				ip_address[INET_ADDRSTRLEN];	 /* ip address for this server 							*/
/*Client Data structure (linked list)*/
	struct client_data 
	{
		SSL *ssl;
		int sock;
		char* client_name; 
		char write[MAX], read[MAX];
		char *r_ptr, *w_ptr;
		LIST_ENTRY(client_data) entries;  /* list */
		bool writeable; 				  /* is there something to write to this client? */
	};

/*Directory Server read and write buffer */
	struct directory_server 
	{
		SSL *ssl; 
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
	char* parsed_message = message + 1; 			/* user message with no overhead      */
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
				if(strncmp(cp->client_name, parsed_message, MAX) == 0 )
				{
					unique_nickname = FALSE;
				}
			}

			/* if nickname is unique, add to client record and generate response */
			if(unique_nickname)
			{
					snprintf(c_data->client_name, MAX, "%s", parsed_message);

					/*generate response */
					snprintf(response, MAX, "j%s has joined the chat.", parsed_message);			
					return 1;
			}
			else
			{
				/*generate response */
				snprintf(response, MAX, "nNickname already exists. Please enter unique nickname: ");
				return 0;
			}
		break;

		/*if first character is a 'c', process chat */
		case 'c':
			/*generate response */
			snprintf(response, MAX, "c%s : %s", c_data->client_name, parsed_message);
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
		sscanf(argv[2], "%d", &port_number);
	}

	/* Init SSL */
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	/* SSL method/ctx for dir. server connection */
	SSL *dirSSL;
	SSL_METHOD *dirMethod;
	SSL_CTX *dirCTX;
	dirMethod = SSLv23_method();
	dirCTX = SSL_CTX_new(dirMethod);
	if(!dirCTX){
		perror("server: directory context creation error");
		exit(1);
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
	} else {


		fprintf(stderr, "%s:%d Connection Established!\n", __FILE__, __LINE__);

		//associate ssl struct to dir socket
		dirSSL = SSL_new(dirCTX);
		if(!dirSSL){
			perror("server: unable to create dir SSL struct");
			exit(1);
		}
		SSL_set_fd(dirSSL, dir_sockfd);

		if(SSL_connect(dirSSL) <= 0){
			perror("server: couldn't establish SSL connection to dir");
			ERR_print_errors_fp(stderr);
			exit(1);
		}

		//set socket as a non-blocking socket
		if(fcntl(dir_sockfd, F_SETFL, O_NONBLOCK) < 0)
		{
			perror("Error setting non-blocking socket.");
		}
		

		/* Read certificates from dir */
		char cryptbuf[1024];
		X509 *cert = SSL_get_peer_certificate(dirSSL);
		X509 *x509 = X509_get_subject_name(cert);
		X509_NAME_oneline(x509, cryptbuf, 1024);
		printf("Subject: %s\n", cryptbuf);

		char dirCommonName[MAX];
		for(int i = 0; i < 1020; i++){
			if(cryptbuf[i] == 'C' && cryptbuf[i+1] == 'N' && cryptbuf[i+2] == '='){
				snprintf(dirCommonName, MAX, "%s", cryptbuf + i + 3);
				break;
			}
		}

		fprintf(stderr, "%s:%d dir common name is: %s...\n Expected: directory_server\n", __FILE__, __LINE__, dirCommonName);
		if(0 != strncmp(dirCommonName, "directory_server", MAX)){
			close(dir_sockfd);
			exit(1);
		}
		
		/*set up directory server struct */
		dir_serv.ssl = dirSSL; //Modified to use the directory ssl for ssl operations
		dir_serv.r_ptr = &(dir_serv.read[0]);


		/* send room name to directory server */
		//snprintf(dir_serv.room_to, MAX, "n,%s", room_name);
		snprintf(dir_response, MAX, "n%s", room_name);
		SSL_write(dirSSL, dir_response, MAX);				// HW6: how should we handle these two write()?	//FIXME

		/* send port number to directory server */
		//snprintf(dir_serv.port_num_to, MAX, "p,%d", port_number);
		snprintf(dir_response, MAX, "p%d", port_number);
		SSL_write(dirSSL, dir_response, MAX);

	}

	/* initialize linked list */
	LIST_INIT(&head);
	
	/* SSL method/ctx for client connections */
	SSL *cliSSL;
	SSL_METHOD *cliMethod;
	SSL_CTX *cliCTX;
	cliMethod = SSLv23_server_method();
	cliCTX = SSL_CTX_new(cliMethod);
	if(!cliCTX){
		perror("server: client context creation error");
		exit(1);
	}

	/* Load certificate based on user provided room name (dir server conn) */
	char fileName[MAX];
	snprintf(fileName, MAX, "%s_chatServer.crt", room_name);
	SSL_CTX_use_certificate_file(cliCTX, fileName, SSL_FILETYPE_PEM);

	SSL_CTX_use_PrivateKey_file(cliCTX, "private.key", SSL_FILETYPE_PEM);
	
	if(!SSL_CTX_check_private_key(cliCTX)){
		fprintf(stderr, "Key doesn't match public certificate.\n");
		exit(1);
	}

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		exit(1);
	}

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

	cliSSL = SSL_new(cliCTX);

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
		FD_SET(dir_sockfd, &writeset);
		FD_SET(dir_sockfd, &readset);
		

		/* re-add all socket descriptors to readset */
     	LIST_FOREACH(np, &head, entries){
			FD_SET(np->sock, &readset);
			FD_SET(np->sock, &writeset);
			
		} 
	
		/* see if any descriptors are ready to be read, wait forever. */
		if ((j=select(max_fd+1, &readset, &writeset, NULL, NULL)) > 0) 
		{

			

			if(FD_ISSET(sockfd,&readset)) 
			{
				/* Accept a new connection request */
				clilen = sizeof(cli_addr);
				new_sockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
				if (0 > new_sockfd) {
					perror("server: accept error");
					exit(1);
				}

				/* Set socket as a non-blocking socket */
				if(fcntl(new_sockfd, F_SETFL, O_NONBLOCK) < 0){
					perror("Error setting non-blocking socket.");
				}
				
				/* Associate SSL struct to newsock */
				SSL *newSSL = SSL_new(cliCTX);
				SSL_set_fd(newSSL, new_sockfd);
				if(SSL_accept(cliSSL) <= 0) {
					ERR_print_errors_fp(stderr);
					exit(1);
				}

				printf("Client connected!");				

			/*store client data in client data structure */
				struct client_data *new_client = (struct client_data *)malloc(sizeof(struct client_data));
				new_client->client_name = (char*)malloc(MAX);
				new_client->sock = new_sockfd;
				new_client->ssl = newSSL;
				new_client->r_ptr = &(new_client->read[0]);
				new_client->w_ptr = &(new_client->write);
				//fprintf(stderr, "\nclient fd: %d\n", (int)(new_client->ssl));
				/* if client is the first client, make this client the head of the linked list and announce event; else, add client to end of list */
				if(0 == client_count)
				{
					LIST_INSERT_HEAD(&head, new_client, entries); 
					c_ptr = new_client;
					snprintf(response, MAX, "jYou are the first to join the chat!\nPlease Enter a nickname:");
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
					
					if(FD_ISSET(np->sock, &readset))
					{
					
						/*if read returns 0 or less, client has disconnected; Else, read message from client */
						if ((nread = SSL_read(np->ssl, np->r_ptr, &(np->read[MAX]) - np->r_ptr)) <= 0) 
						{	
							/* error checking */
							if(errno != SSL_ERROR_WANT_READ)
							{ 
								perror("read error on socket"); 
							}
							else if(0 == nread)
							{
								fprintf(stderr, "%s:%d: EOF on socket\n", __FILE__, __LINE__);
							}
							/* Remove client from list */
							SSL_shutdown(np->ssl);
							SSL_free(np->ssl);
							close(np->sock);
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
						else if(0 < nread){
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
							if(1 == handle_ret)
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
						if(0 == handle_ret)
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
				if(np2->writeable && FD_ISSET( np2->sock, &writeset) && ((wb_space = &(np2->write[MAX]) - np2->w_ptr) > 0))
				{
						if((nwritten = SSL_write(np2->ssl, np2->w_ptr, wb_space)) < 0){
							if (errno != SSL_ERROR_WANT_WRITE) { perror("write error on socket"); }
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