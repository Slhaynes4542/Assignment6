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

//inet_ntop()

/* enums */
enum connection_type 
{
	SERVER,
	CLIENT
};

/* global variables */
char 				response[MAX];					/* response to send to clients  	   */
int 				server_count = 0;				/* number of chat servers connected */ 	

/*client Data structure (linked list)*/
	struct connection_data 
	{
		int conn_fd;								//socket
		enum connection_type type;					//Server or Client Connection
		char room_name[MAX];						//string holding room name(Server only)
		char ip_address[INET_ADDRSTRLEN];			//Ip Add(Server only)
		int port_number;							//Port num(Server only)
		char sendBuff[MAX];							//send buffer
		char readBuff[MAX];							//read buffer
		char *sendptr;								//pointer that it the start of the send buffer
		char *sendIndexptr;							//pointer that points to where we are at so far in the send buff
		char *readptr;								//pointer that is at the start of the read buffer
		char *readIndexptr;							//pointer that points to where we are so far in the read buff
		LIST_ENTRY(connection_data) entries;		/* list */
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

int HandleMessage(char * message, struct connection_data* c_data, struct listhead head)
{
	char* parsed_message = message + 2; 			/* user message with no overhead      		*/
	struct connection_data * cp;					/* pointer for traversing client data 		*/
	bool	unique_chatroom = TRUE;			   		/* is the chat room name specified unique?  */
	bool 	unique_port = TRUE;						/* is the server port unique? 				*/
	int i = 1;										/* index variable for loop					*/

	switch(message[0])
	{
		/*connection is a chat server and is providing chat room name, set the connection type and name, TO-DO: check for duplicate names */
		case 'n':
			/*process */
			LIST_FOREACH(cp, &head, entries)
			{
				/* check for duplicate nicknames, set flag */
				if(strcmp(cp->room_name, parsed_message) == 0 )
				{
					unique_chatroom = FALSE;
				}
			}

			/* if chat room name is unique, add to connection record and generate a response */
			if(unique_chatroom)
			{
				snprintf(c_data->room_name, MAX, parsed_message);
				/* generate response */
				snprintf(response, MAX,"d,Chat Room Opened!");
			}
			/*else, server needs to specify a new chat room name*/
			else
			{
				snprintf(response, MAX, "e");
			}
			
			c_data->type = SERVER;
			server_count++;
			fprintf(stderr, "%s:%d Chat Room name: %s\n", __FILE__, __LINE__, c_data->room_name);			
			break;

		/* connection is server and is supplying port number, set port number */
		case 'p':
			
			c_data->port_number = atoi(parsed_message);//TODO: replace atoi()?
			fprintf(stderr, "%s:%d Port Number: %d\n", __FILE__, __LINE__, c_data->port_number);
			break;
		/* recieve ip address from chat server */
		case 'i':
			snprintf(c_data->ip_address, MAX, "%s", parsed_message);
			fprintf(stderr, "%s:%d Chat Server IP: %s\n", __FILE__, __LINE__, c_data->ip_address);
			break; 
		/* connection is a chat client, set the connections type */
		case 'c':
			c_data->type = CLIENT;

			/* if there are available chat servers, send their chat room name to the client */
			if(server_count != 0)
			{
				memset(response, 0, sizeof(response));
				LIST_FOREACH(cp, &head, entries)
				{
					if(cp->type == SERVER)
					{
						snprintf(response, MAX, "d,%d. %s", i, cp->room_name);
						write(c_data->conn_fd, response, MAX);//TODO: nonblocking
						i++;
					}
				}
				snprintf(response, MAX, "c,Enter the name of the chat server you want to join: ");
				write(c_data->conn_fd, response, MAX);//TODO: nonblocking
				return -1;
			}
			else
			{
				snprintf(response, MAX, "There are no available chat servers.");
			}
			break;
		/* recieved chat room connection request from client */
		case 'r':
			
			/*check if the response matches a chat room name */
			LIST_FOREACH(cp, &head, entries)
				{
					/*if client specifies a chat room to join, send the servers information to the client */
					if(strcmp(cp->room_name, parsed_message) == 0)
					{
						/* send chat server ip address */
						memset(response, 0, sizeof(response));
						snprintf(response, MAX, "i,%s", cp->ip_address);
						write(c_data->conn_fd, response, MAX);//TODO: nonblocking
						/* send chat server port number */
						memset(response, 0, sizeof(response));
						snprintf(response, MAX, "p,%i", cp->port_number);
						write(c_data->conn_fd, response, MAX);//TODO: nonblocking
						return -1;
					}
				}
				return 0;
			break;
		default:
			fprintf(stderr, "%s:%d Error reading from connection\n", __FILE__, __LINE__);
			return -1;
		break;		

	}
	return 1;
}

int main(int argc, char **argv)
{
	int						sockfd, new_sockfd;			/* listening socket and new socket file descriptor		*/
	unsigned int			clilen;						/* client length 										*/
	struct sockaddr_in		cli_addr, serv_addr;		/* socket, client, and server addresses				    */
	char					s[MAX];
	fd_set 					readset;					/* set of file descriptors (sockets) available to read  */
	fd_set 					writeset;					/* set of file descriptors (sockets) available to write */
	int 					max_fd = 0;					/* maximum file descriptor in readset 					*/
	int 					j, nread, nwrite;
	int						wb_space;					/* available write buffer space							*/						
	struct listhead			head;						/* head of linked list containing client data			*/
	struct connection_data	*c_ptr; 		 			/* pointers to client data 								*/
	struct connection_data	*np;						/* pointer used for traversing list         		    */
	struct connection_data	*np2; 						/* pointer used for traversing list   					*/	
	int 					conn_count = 0; 			/* number of clients connected to the server 			*/
	int 					handle_ret;					/* return value for HandleMessage() 					*/
	char 					ip_add[INET_ADDRSTRLEN]; 	/* string to store an ip address						*/
	

	/* Create communication endpoint */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("directory server: can't open stream socket");
		exit(1);
	}

	/* Bind socket to local address */
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family		= AF_INET;
	serv_addr.sin_addr.s_addr	= htonl(INADDR_ANY);
	serv_addr.sin_port			= htons(SERV_TCP_PORT);

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("directory server: can't bind local address");
		exit(1);
	}

	/* set max file descriptor */
	max_fd = sockfd;

	/* specify that the listening socket is listening for 5 connections */
	listen(sockfd, 5);

	clilen = sizeof(cli_addr);

	for (;;) {

		fflush(stdout);
		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_SET(0, &readset);
		FD_SET(sockfd, &readset);

		/* re-add all socket descriptors to readset */
     	LIST_FOREACH(np, &head, entries){
			FD_SET(np->conn_fd, &readset);
		} 

		/* see if any descriptors are ready to be read, wait forever. */
		if ((j=select(max_fd+1,&readset,&writeset,NULL,NULL)) > 0) 
		{
			fprintf(stderr, "entered select.");//debug
			if(FD_ISSET(sockfd,&readset))
			{
				/* Accept a new connection request */
				clilen = sizeof(cli_addr);
				new_sockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
				if (new_sockfd < 0) {
					perror("server: accept error");
					close(new_sockfd);//close new socket?
					exit(1);//exit?
				}
				/*set new socket as nonblocking*/
				if(fcntl(new_sockfd, F_SETFL, O_NONBLOCK) < 0){
					perror("Error setting non-blocking socket.");
				}
				/* get server ip address */
				//inet_ntop(AF_INET, &(cli_addr.sin_addr.s_addr), ip_add, INET_ADDRSTRLEN);		

				char ip_add[INET_ADDRSTRLEN];
				if (inet_ntop(AF_INET, &(cli_addr.sin_addr), ip_add, INET_ADDRSTRLEN) == NULL) {
					perror("inet_ntop");
					exit(1);
				}
				printf("Client IP address: %s\n", ip_add);//debug
			
				/*store client data in client data structure */
				struct connection_data *new_conn = (struct connection_data *)malloc(sizeof(struct connection_data));
				new_conn->conn_fd = new_sockfd;
				strncpy(new_conn->ip_address, ip_add, INET_ADDRSTRLEN);
				/*init buffer pointers*/
				new_conn->conn_fd = new_sockfd;
				new_conn->readptr = new_conn->readBuff;
				new_conn->readIndexptr = new_conn->readBuff;
				new_conn->sendptr = new_conn->sendBuff;
				new_conn->sendIndexptr = new_conn->sendBuff;
				fprintf(stderr, "\nchat server ip: %s\n", new_conn->ip_address);//debug
				fprintf(stderr, "\nconnection fd: %d\n", new_conn->conn_fd);//debug

				/* if connection is the first connection, make this connection the head of the linked list; else, add connection to end of list */
				if(conn_count == 0 )//TODO: change to check for null list, get rid of conn_count var
				{
					LIST_INSERT_HEAD(&head, new_conn, entries); 
					c_ptr = new_conn;
				}
				else
				{
					LIST_INSERT_AFTER(c_ptr, new_conn, entries);
					c_ptr = new_conn;
				}
				
				/*increment connection count */
				conn_count++;
				/*update max file descriptor */
				if(max_fd < new_sockfd)
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
					if(FD_ISSET(np2->conn_fd, &writeset) && ((wb_space = &(np2->sendBuff[MAX]) - np2->sendptr) > 0))
					{
						if((nwrite = write(np2->conn_fd, np2->sendptr, wb_space)) < 0){
							if (errno != EWOULDBLOCK) { perror("write error on socket"); }
						}
						else{
							/*increment write buffer pointer */
							np2->sendptr += nwrite;
							
							/* check if entire message has been written */
							if(&(np2->sendBuff[MAX]) == np2->sendptr){
								memset(np2->sendBuff, 0, MAX);
								np2->sendptr = &(np2->sendBuff[0]); 
							}
							else{
								FD_SET(np2->conn_fd, &writeset);
							}
						}
					}
					
					/*process reads*/
					if(FD_ISSET(np->conn_fd, &readset))
					{
						if((nread = read(np->conn_fd, np->readptr, &(np->readBuff[MAX]) - np->readptr)) <= 0)
						{
							if(errno != EWOULDBLOCK)
							{
								perror("read error from socket");
								if(FD_ISSET(np->conn_fd, &readset) && FD_ISSET(np->conn_fd, &writeset))
								{
									fprintf(stderr, "%s:%d Readable and writeable, closing\n", __FILE__, __LINE__);
									/* Remove connection from list */

									/* if connection is a chat server, decrement count of chat servers */
									if(np->type == SERVER)
									{
										server_count--;
									}
									LIST_REMOVE(np, entries);
									close(np->conn_fd);
									free(np);
									conn_count--;
									/* set c_ptr to the end of the list */
									LIST_FOREACH(np2, &head, entries)
									{
										if(LIST_NEXT(np2, entries) == NULL)
										{
											c_ptr = np2;
										}
									}
								}
							}else if(0 == nread){
								fprintf(stderr, "%s:%d EOF on this socket\n", __FILE__, __LINE__);
								//LIST_REMOVE(np, entries);
								//close(np->conn_fd);
								//free mem
								//free(np); //maybe
							}
						}
						else
						{//nread > 0
							handle_ret = HandleMessage(np->readptr, np, head); 

							/* If HandleMessage() return 1, then stage response */
							if(handle_ret == 1)
							{
								if(np->sendptr == &(np->sendBuff[0]))//TODO:verify this is correct
								{
									strncpy(np->sendptr, response, MAX);
								}
								FD_SET(np->conn_fd, &writeset);
							}
							/* if HandleMessage() return 0, client entered invalid chat room name */
							if(handle_ret== 0)
							{
								snprintf(response, MAX, "v,Enter the name of the chat server you want to join:");
								if(np->sendptr == &(np->sendBuff[0]))//TODO:verify this is correct
								{
									strncpy(np->sendptr, response, MAX);
								}
								FD_SET(np->conn_fd, &writeset);
								//write(np->conn_fd, response, MAX);
							}
						}		
					}
				}
			}
		}
	}
}
