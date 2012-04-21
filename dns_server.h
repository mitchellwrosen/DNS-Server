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
   void Respond(DnsQuery query, bool recursive);

  protected:

  private:
   DnsCache cache_;

   const std::string port_;
   char buf_[ETH_DATA_LEN];
};

#endif   // _DNS_SERVER_H_
