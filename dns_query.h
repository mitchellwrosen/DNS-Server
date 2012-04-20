#ifndef _DNS_QUERY_H_
#define _DNS_QUERY_H_

#include <stdint.h>

#include <string>

#include "dns_packet.h"

class DnsQuery {
  public:
   DnsQuery(DnsPacket& data);

   void Print();

   // Getters
   std::string name() { return name_; }
   uint16_t type() { return type_; }
   uint16_t clz() { return clz_; }

  private:
   std::string name_;
   uint16_t type_;
   uint16_t clz_;
};

#endif   // _DNS_QUERY_H_
