#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>


#define SERV_TCP_PORT 45231

/* Change the following to be your host addr: 129.130.10.43 for viper and 129.130.10.39 for cougar */
#define SERV_HOST_ADDR "129.130.10.43"
