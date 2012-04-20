#ifndef _DNS_CACHE_H_
#define _DNS_CACHE_H_

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

#include <map>
#include <pair>
#include <vector>

#include "smartalloc.h"

#include "dns_query"
#include "dns_resource_record.h"
#include "dns_packet.h"

class DnsCache {
  public:
   DnsCache();

   std::list<DnsResourceRecord> Get(DnsQuery& query);

   typedef std::map<DnsQuery, std::list<std::pair<
         time_t, DnsResourceRecord> > > Cache;
  
  private:

   Cache cache_;
};

#endif   // _DNS_CACHE_H_
