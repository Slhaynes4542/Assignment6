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

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* enums */
enum connection_type
{
	UNKNOWN,
	SERVER,
	CLIENT
};

/* global variables */

/*client Data structure (linked list)*/
struct connection_data
{
	int conn_fd;							/* socket										*/
	SSL *ssl;								/* SSL endpoint									*/
	enum connection_type type;				/* Server or Client Connection					*/
	char room_name[MAX];					/* string holding room name(Server only)		*/
	char ip_address[INET_ADDRSTRLEN];		/* Ip Address(Server only)						*/
	int port_number;						/* Port num(Server only)						*/
	char sendBuff[MAX];						/* send buffer									*/
	char readBuff[MAX];						/* read buffer									*/
	LIST_ENTRY(connection_data)	entries;	/* list											*/
	bool ssl_connected;						/* is ssl connection established?				*/
	bool writeable;							/* workaround for socket stuck in writeset?		*/

};

LIST_HEAD(listhead, connection_data);

/*************************************************
* Method: HandleMessage
* Description: Handles messages received from
			   clients
* Params: (message - message to handle)
* 		  (c_data - client data)
*		  (head - head of the client list )
* Return: (1 - message is handled or nickname is
		   valid )
		  (0 - client entered invalid chat name)
		  (-1 - do not write a message  )
*************************************************/

int HandleMessage(char *message, struct connection_data *c_data, struct listhead head)
{
	char *parsed_message = message + 2; /* user message with no overhead      			*/
	char response[MAX];					/* response to send to clients					*/
	struct connection_data *cp;			/* pointer for traversing client data 			*/
	bool unique_chatroom = TRUE;		/* is the chat room name specified unique?  	*/
	bool unique_port = TRUE;			/* is the server port unique? 					*/
	int i = 1;							/* index variable for loop						*/
	char temp[MAX];						/* temp char array for building response string */

	switch (message[0])
	{
	/*connection is a chat server and is providing chat room name, set the connection type and name, TO-DO: check for duplicate names */
	case 'n':
		if (!LIST_EMPTY(&head))
		{
			/*process */
			LIST_FOREACH(cp, &head, entries)
			{
				/* check for duplicate nicknames, set flag */
				if (strcmp(cp->room_name, parsed_message) == 0)
				{
					unique_chatroom = FALSE;
				}
			}
		}
		/* if chat room name is unique, add to connection record and generate a response */
		if (unique_chatroom)
		{
			snprintf(c_data->room_name, MAX, parsed_message);//save room name
			snprintf(c_data->sendBuff, MAX, "d,Chat Room Opened!");//response to chat server
		}
		else	/*else, server needs to specify a new chat room name*/
		{
			snprintf(c_data->sendBuff, MAX, "e");
		}
		c_data->writeable = TRUE;///flag client as having data to write
		c_data->type = SERVER;
		fprintf(stderr, "%s:%d Chat Room name: %s\n", __FILE__, __LINE__, c_data->room_name);//debug
		break;//goto return 1
	/* connection is server and is supplying port number, set port number */
	case 'p':
		c_data->port_number = atoi(parsed_message);//TODO: replace atoi()?
		fprintf(stderr, "%s:%d Port Number: %d\n", __FILE__, __LINE__, c_data->port_number);//debug
		break;//goto return 1
	/* recieve ip address from chat server(and port number) */
	case 'i':
		snprintf(temp, MAX, "%s", parsed_message);
		const char delim[2] = "|"; // delimiter for tokenization
		char *tok;				   // token ref
		// be very careful with strtok()
		tok = strtok(temp, delim);
		if (tok != NULL)
		{
			snprintf(c_data->ip_address, MAX, "%s", tok);
			fprintf(stderr, "%s:%d Chat Server IP: %s\n", __FILE__, __LINE__, c_data->ip_address); // debug
			tok = strtok(NULL, delim);
			if (tok != NULL)
			{
				/* assuming next token is port number TODO:error handling */
				c_data->port_number = atoi(tok);													 // TODO: replace atoi()?
				fprintf(stderr, "%s:%d Port Number: %d\n", __FILE__, __LINE__, c_data->port_number); // debug
			}
			else //no port number
			{
				fprintf(stderr, "%s:%d Error reading Chat Server Port Number.\n", __FILE__, __LINE__);
				exit(1);//should only reach this point by malicious action
			}
		}
		else //no ip recieved/nothing recieved
		{
			fprintf(stderr, "%s:%d Error reading Chat Server IP.\n", __FILE__, __LINE__);
			exit(1);//should only reach this point by malicious action
		}
		break;
	/* connection is a chat client, set the connections type */
	case 'c':
		c_data->type = CLIENT;

		/* if there are available chat servers, send their chat room name to the client				*/
		/* Assuming all server names fit into 51=MAX-(2+15+5+27):(2(d,)+15(#, )+5(\n)+27(prompt))	*/
		/* If server names exceed 51 chars total, this needs to be refactored						*/
		if (!LIST_EMPTY(&head))
		{
			memset(response, 0, sizeof(response));
			LIST_FOREACH(cp, &head, entries)
			{
				if (cp->type == SERVER)
				{
					if (1 == i)
					{ // first line
						snprintf(temp, MAX, "d,%d. %s\n", i, cp->room_name);
						strncpy(response, temp, MAX);
					}
					else
					{ // next 4 lines
						snprintf(temp, MAX, "%d. %s\n", i, cp->room_name);
						strncat(response, temp, MAX); // append to previous lines
					}
					i++;
				}
			}
			snprintf(temp, MAX, "Enter server name to join: ");//stage user prompt
			strncat(response, temp, MAX); // append prompt to server list	
			snprintf(c_data->sendBuff, MAX, "%s", response);
			c_data->writeable = TRUE;///flag client as having data to write
			return 1;
			//break;
		}
		else
		{
			snprintf(c_data->sendBuff, MAX, "There are no available chat servers.");
			c_data->writeable = TRUE;//flag client as having data to write
		}
		break;
	/* recieved chat room connection request from client */
	case 'r':
		/*check if the response matches a chat room name */
		LIST_FOREACH(cp, &head, entries)
		{
			/*if client specifies a chat room to join, send the servers information to the client */
			if (strcmp(cp->room_name, parsed_message) == 0)
			{
				/*send ip, port, and room name with format: ip|port|roomname*/
				memset(response, 0, sizeof(response));
				snprintf(response, MAX, "i,%s|", cp->ip_address);//add ip to response
				snprintf(temp, MAX, "%i|", cp->port_number);//stage port number
				strncat(response, temp, MAX);//add port to response
				snprintf(temp, MAX, "%s", cp->room_name);//stage chat room name
				strncat(response, temp, MAX);//add chat room name to response
				snprintf(c_data->sendBuff, MAX, "%s", response);//put response in client's send buffer
				c_data->writeable = TRUE;//flag client as having data to write
				break;//goto return 1
			}
		}
		snprintf(c_data->sendBuff, MAX, "v,Enter the name of the chat server you want to join:");
		c_data->writeable = TRUE;//flag client as having data to write
		return 0;
		break;
	default:
		fprintf(stderr, "%s:%d Error reading from connection, got %s\n", __FILE__, __LINE__, message);//debug
		return -1;
		break;
	}
	return 1;
}

int main(int argc, char **argv)
{
	int sockfd, new_sockfd;					/* listening socket and new socket file descriptor		*/
	unsigned int clilen;					/* client length 										*/
	struct sockaddr_in cli_addr, serv_addr; /* socket, client, and server addresses				    */
	char s[MAX];
	fd_set readset;							/* set of file descriptors (sockets) available to read  */
	fd_set writeset;						/* set of file descriptors (sockets) available to write */
	int max_fd = 0;							/* maximum file descriptor in readset 					*/
	int j, nread, nwrite;
	struct listhead head;					/* head of linked list containing client data			*/
	struct connection_data *c_ptr;			/* pointers to client data 								*/
	struct connection_data *np;				/* pointer used for traversing list         		    */
	struct connection_data *np2;			/* pointer used for traversing list   					*/
	//int conn_count = 0;			   		/* number of clients connected to the server 			*/
	int handle_ret;							/* return value for HandleMessage() 					*/
	char ip_add[INET_ADDRSTRLEN];			/* string to store an ip address						*/
	/************************************************************/
	/*** Initialize Server SSL state                          ***/
	/************************************************************/
	SSL *ssl;							/* ssl var */
	int ssl_err;						/* ssl error return */
	SSL_METHOD *method;					/* SSL method */
	SSL_CTX *ctx;						/* SSL context */
	OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
	SSL_load_error_strings();			/* Load/register error msg */
	method = TLS_server_method();		/* Create new server-method */
	ctx = SSL_CTX_new(method);			/* Create new context */
	/* Load certificate and private key files */
	SSL_CTX_use_certificate_file(ctx, "directory_server.crt", SSL_FILETYPE_PEM); /* set the local certificate from CertFile */
	SSL_CTX_use_PrivateKey_file(ctx, "private.key", SSL_FILETYPE_PEM);			 /* set private key from KeyFile */
	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Key & certificate don't match");
		exit(1);
	}

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("directory server: can't open stream socket");
		exit(1);
	}

	/* Bind socket to local address */
	memset((char *)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(SERV_TCP_PORT);

	if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("directory server: can't bind local address");
		exit(1);
	}

	/* set max file descriptor */
	max_fd = sockfd;
	clilen = sizeof(cli_addr);

	/* specify that the listening socket is listening for 5 connections */
	listen(sockfd, 5);

	/* Directory Server init done, Loop until termination */
	for (;;)
	{
		fflush(stdout);
		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_SET(sockfd, &readset);

		/* re-add all socket descriptors to readset */
		LIST_FOREACH(np, &head, entries)
		{
			FD_SET(np->conn_fd, &readset);
			if(np->writeable == TRUE){//if write flag set, add to writeset
				FD_SET(np->conn_fd, &writeset);
			}
		}

		/* see if any descriptors are ready to be read, wait forever. */
		if ((j = select(max_fd + 1, &readset, &writeset, NULL, NULL)) > 0)
		{
			fprintf(stderr, "entered select.\n"); // debug
			if (FD_ISSET(sockfd, &readset))
			{
				/* Accept a new connection request */
				clilen = sizeof(cli_addr);
				new_sockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
				if (new_sockfd < 0)
				{
					perror("server: accept error");
					close(new_sockfd); // TODO: close new socket?
					exit(1);		   // TODO: exit?
				}

				/* get server ip address */
				// inet_ntop(AF_INET, &(cli_addr.sin_addr.s_addr), ip_add, INET_ADDRSTRLEN);

				char ip_add[INET_ADDRSTRLEN];
				if (inet_ntop(AF_INET, &(cli_addr.sin_addr), ip_add, INET_ADDRSTRLEN) == NULL)
				{
					perror("inet_ntop");
					exit(1);
				}
				printf("Client IP address: %s\n", ip_add); // debug

				/*store client data in client data structure */
				struct connection_data *new_conn = (struct connection_data *)malloc(sizeof(struct connection_data));
				new_conn->conn_fd = new_sockfd;
				strncpy(new_conn->ip_address, ip_add, INET_ADDRSTRLEN);
				/*init buffer pointers*/
				new_conn->conn_fd = new_sockfd;
				new_conn->ssl_connected = FALSE;
				new_conn->writeable = FALSE;
				fprintf(stderr, "\nchat server ip: %s\n", new_conn->ip_address); // debug
				fprintf(stderr, "\nconnection fd: %d\n", new_conn->conn_fd);	 // debug

				
				/* if connection is the first connection, make this connection the head of the linked list; else, add connection to end of list */
				if (LIST_EMPTY(&head))//returns true if list is empty
				{
					LIST_INSERT_HEAD(&head, new_conn, entries);
					c_ptr = new_conn;
				}
				else
				{
					LIST_INSERT_AFTER(c_ptr, new_conn, entries);
					c_ptr = new_conn;
				}
				/*update max file descriptor */
				if (max_fd < new_sockfd)
				{
					max_fd = new_sockfd;
				}
			}
			else
			{
				/*else, process socket IO */
				LIST_FOREACH(np, &head, entries)
				{
					/* if fd is in writeset, then process pending write */
					if (np->writeable && FD_ISSET(np->conn_fd, &writeset) )
					{
						fprintf(stderr, "In write set\n");
						if ((nwrite = SSL_write(np->ssl, np->sendBuff, MAX)) < 0)
						{
							ssl_err = SSL_get_error(np->ssl, nwrite);
							perror("write error on socket");
							if(ssl_err == SSL_ERROR_WANT_WRITE){
								perror("SSL data awaiting write");
							}
						}
						else if(nwrite > 0){
							np->writeable = FALSE;
						}
					}

					/*process reads*/
					if (FD_ISSET(np->conn_fd, &readset))
					{
						if (!np->ssl_connected)
						{
							/*** Create SSL session state based on context & SSL_accept */
							np->ssl = SSL_new(ctx); /* init SSL state using context		*/
							if (!np->ssl)
							{
								perror("directory: unable to create dir SSL struct");
								exit(1);
							}

							SSL_set_fd(np->ssl, np->conn_fd); /* associate SSL state with socket	*/
							if (SSL_accept(np->ssl) == 0)
							{
								ERR_print_errors_fp(stderr);
							}

							/*set new socket as nonblocking*/
							if (fcntl(np->conn_fd, F_SETFL, O_NONBLOCK) < 0)
							{
								perror("Error setting non-blocking socket.");
							}
							np->ssl_connected = TRUE;
						}
						else
						{
							if(SSL_pending() > 0)
							{
								if ((nread = SSL_read(np->ssl, np->readBuff, MAX)) <= 0)
								{
									perror("SSL read error");
									ssl_err = SSL_get_error(np->ssl, nread);
									//TODO: do SSL error handling //currently checking nread and socket read/write works fine
									if (FD_ISSET(np->conn_fd, &readset) && FD_ISSET(np->conn_fd, &writeset))
									{
										snprintf(s, MAX, "Connection to %s closed", np->ip_address);
										fprintf(stderr, "%s", s);//print to stderr
										memset(s, 0, MAX);
										LIST_REMOVE(np, entries);
										close(np->conn_fd);
										free(np);
										/* set c_ptr to the end of the list */
										LIST_FOREACH(np2, &head, entries)
										{
											if (LIST_NEXT(np2, entries) == NULL)
											{
												c_ptr = np2;
											}
										}
									}
									else if(ssl_err == SSL_ERROR_WANT_READ){
										perror("SSL data awaiting read");
									}
								}
								else
								{ // nread > 0
									handle_ret = HandleMessage(np->readBuff, np, head);
									if (handle_ret < 0)//invalid message
									{
										fprintf(stderr, "%s:%d Invalid return from HandleMessage\n", __FILE__, __LINE__);
										exit(1);
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
