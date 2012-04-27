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

   void Run();
   bool Resolve(DnsQuery& query, uint16_t id, uint16_t* response_code);

   int ReadIntoBuffer(struct sockaddr* client_addr, socklen_t* client_addr_len);

   // Sends a DnsQuery to an upstream server, fills in addr info (TODO i6)
   void SendQueryUpstream(struct sockaddr* addr, socklen_t addrlen,
         DnsQuery& query);

   // Caches all resource records of a packet.
   void CacheAllResourceRecords(DnsPacket& packet);

   // Sends buf_ to the specified address.
   void SendBufferToAddr(struct sockaddr* addr, socklen_t addrlen, int datalen);

  protected:

  private:
   DnsCache cache_;

   const int port_;
   const std::string port_str_;
   int cur_id_; // Use unique id for each upstream query.


   char buf_[ETH_DATA_LEN];
};

#endif   // _DNS_SERVER_H_
