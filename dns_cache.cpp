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

#include "smartalloc.h"

#include "dns_resource_record.h"
#include "dns_packet.h"
#include "dns_cache.h"

DnsCache::DnsCache() {
   // inialize with root servers
}

std::list<DnsResourceRecord> DnsCache::Get(DnsQuery& query) {
   Cache::iterator it = cache_.find(query);
   
   // Cache hit - return it
   if (it != cache_.end()) {
      
   }

   // Cache miss - if recursive,  
   else {
      //Get(query, recursive);
   }
}
