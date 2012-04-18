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

#include "smartalloc.h"
#include "dns_packet.h"

class DnsCache {
  public:
   DnsCache();
   virtual ~DnsServer();

   void Run();

  protected:

  private:
   // Mapping of queries to responses
   std::map<DnsPacket::Query, DnsPacket::ResourceRecord> map;
};

#endif   // _DNS_CACHE_H_
