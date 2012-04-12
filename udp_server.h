#ifndef _UDP_SERVER_H_
#define _UDP_SERVER_H_

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "checksum.h"
#include "smartalloc.h"
#include "server.h"

class UDPServer : public Server {
  public:
   virtual void Run() = 0;
};

#endif   // _UDP_SERVER_
