#ifndef _DNS_SERVER_H_
#define _DNS_SERVER_H_

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
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

#include "dns_query.h"
#include "dns_cache.h"
#include "udp_server.h"

class DnsServer : public UdpServer {
  public:
   DnsServer();
   virtual ~DnsServer();

   void ReadIntoBuffer(struct sockaddr* client_addr,
                       socklen_t* client_addr_len);
   void ReadIntoBuffer();

   void Run();
   void Resolve(DnsQuery query, uint16_t id);

   void SendQuery(char* ip, int iplen, std::string name, uint16_t type,
         uint16_t clz, uint16_t id);
   void SendQuery(char* ip, int iplen, DnsQuery& query, uint16_t id);

   // Sends buf_ to the specified ip address, port 53
   void SendBufferToIp(char* ip, int iplen, int datalen);

  protected:

  private:
   DnsCache cache_;

   const std::string port_;
   char buf_[ETH_DATA_LEN];
};

#endif   // _DNS_SERVER_H_
