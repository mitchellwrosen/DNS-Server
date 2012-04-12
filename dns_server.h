#ifndef _DNS_SERVER_H_
#define _DNS_SERVER_H_

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
#include "udp_server.h"



class DNSServer : public UDPServer {
  public:
   DNSServer();
   void Run();
  private:
   const std::string port_;
};

#endif   // _DNS_SERVER_H_
