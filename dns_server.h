#ifndef _DNS_SERVER_H_
#define _DNS_SERVER_H_

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
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

void sigint_handler(int signum);

class DNSServer : public UDPServer {
  public:
   DNSServer();
   void Run();

  protected:
   class DNSPacket {
     public:
      DNSPacket(char* data);

      char* Question(int index);
      char* Answer(int index);
      char* Authority(int index);
      char* Additional(int index);

     private:
      int id_;
      int rrs_answer_;
      int rrs_authority_;
      int rrs_additional_;
   };

  private:
   const std::string port_;
};

#endif   // _DNS_SERVER_H_
