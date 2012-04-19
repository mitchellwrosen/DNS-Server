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

#include "smartalloc.h"

#include "dns_resource_record.h"
#include "dns_packet.h"

class DnsCache {
  public:
   DnsCache();

  private:
   // Mapping of strings to resource records
   std::map<std::string, DnsResourceRecord> map_;
};

#endif   // _DNS_CACHE_H_
