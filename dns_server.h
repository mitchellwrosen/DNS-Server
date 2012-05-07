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

#include <list>

#include "checksum.h"
#include "smartalloc.h"

#include "dns_packet.h"
#include "dns_cache.h"
#include "udp_server.h"

class DnsServer : public UdpServer {
  public:
   DnsServer();
   virtual ~DnsServer();

   struct QueryInfo {
      //QueryInfo(DnsQuery query, RRList& authority_rrs, RRList& additional_rrs);
      QueryInfo(DnsQuery& query, RRList& authority_rrs, RRList& additional_rrs);

      DnsQuery query_;
      RRList authority_rrs_;
      RRList additional_rrs_;
   };

   typedef std::list<QueryInfo, STLsmartalloc<QueryInfo> > QueryInfoList;

   struct ClientInfo {
      ClientInfo(struct sockaddr_storage client_addr, socklen_t client_addr_len,
            uint16_t id, DnsQuery& query, RRList& authority_rrs,
            RRList& additional_rrs);

      struct sockaddr_storage client_addr_;
      socklen_t client_addr_len_;
      uint16_t id_;   // network order
      time_t timeout_; // host order
      QueryInfoList query_info_list_;

      // Compare ids
      bool operator==(const uint16_t id) const;

      // Compare ClientInfos by timeout, reverse. This is so a low timeout
      // (i.e. ending soon) will put the ClientInfo at the top of the heap.
      bool operator<(const struct ClientInfo& client_info) const;
   };

   typedef std::vector<ClientInfo, STLsmartalloc<ClientInfo> > ClientInfoVec;

   // Update the timeout of the specified ClientInfo (by id) to NOW + 2 seconds.
   // Also sort the list, so that the lowest timeout is on top.
   // Return true if the update was successful (it always should be).
   bool UpdateTimeout(uint16_t id);

   void Run();
   bool Resolve(DnsQuery& query, uint16_t id, uint16_t* response_code);

   int ReadIntoBuffer(struct sockaddr* client_addr, socklen_t* client_addr_len);

   // Sends the top query of a ClientInfo upstream, after possible pushing
   // more queries to resolve (such as A records of NS)
   void SendQueryUpstream(ClientInfo* client_info);

   // Sends a DnsQuery to an upstream server, fills in addr info (TODO i6)
   void SendQueryUpstream(struct sockaddr* addr, socklen_t addrlen,
         DnsQuery& query, uint16_t id);

   // Caches all resource records of a packet.
   void CacheAllResourceRecords(DnsPacket& packet);
   void CacheAllResourceRecords(DnsPacket& packet, DnsQuery& query);

   // Sends buf_ to the specified address.
   void SendBufferToAddr(struct sockaddr* addr, socklen_t addrlen, int datalen);

  private:
   DnsCache* cache_;

   ClientInfoVec client_info_vec_;

   char buf_[ETH_DATA_LEN];

   const int port_;
   const std::string port_str_;
};

#endif   // _DNS_SERVER_H_
