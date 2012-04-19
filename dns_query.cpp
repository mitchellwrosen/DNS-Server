#include <arpa/inet.h>
#include <stdint.h>

#include <iostream>

#include "dns_packet.h"
#include "dns_query.h"

DnsQuery::DnsQuery(char* data) {
   // NULL pointer to packet, because the name is always going to be a full
   // string. Thus there will be no resolving pointers by the offset into the
   // packet.
   name_ = DnsPacket::GetName(NULL, &data);
   type_ = ntohs(*((uint16_t*) data));
   clz_ = ntohs(*((uint16_t*) (data + 2)));
}

void DnsQuery::Print() {
   std::cout << "Query:" << std::endl;
   std::cout << "   Name: %s" << name_ << std::endl;
   std::cout << "   Type: %d" << type_ << std::endl;
   std::cout << "   Class: %d" << clz_ << std::endl;
}
