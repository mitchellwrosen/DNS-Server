#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include <iostream>

#include "checksum.h"
#include "smartalloc.h"

#include "dns_packet.h"

namespace constants = dns_packet_constants;

DnsQuery::DnsQuery(DnsPacket& packet) {
   name_ = packet.GetName();

   type_ = *((uint16_t*) packet.cur_);
   clz_ = *((uint16_t*) (packet.cur_ + 2));

   packet.cur_ += 4;
}

DnsQuery::DnsQuery(std::string name, int type, int clz)
   : name_(name), type_(type), clz_(clz) { }

bool DnsQuery::operator<(const DnsQuery& query) const {
   // First compare names
   if (name_ != query.name_)
      return name_ < query.name_;

   // Then types
   if (type_ != query.type_)
      return type_ < query.type_;

   // Then classes
   return clz_ < query.clz_;
}

char* DnsQuery::Construct(OffsetMap* offset_map, char* p, char* packet) const {
  p = DnsPacket::ConstructDnsName(offset_map, p, packet, name_);

  memcpy(p, &type_, 2);
  memcpy(p + 2, &clz_, 2);

  return p + 4;
}

void DnsQuery::Print() const {
   std::cout << "Query:" << std::endl;
   std::cout << "   Name: " << name_ << std::endl;
   std::cout << "   Type: " << ntohs(type_) << std::endl;
   std::cout << "   Class: " << ntohs(clz_) << std::endl;
}

std::string DnsQuery::ToString() const {
   std::string ret;

   ret.push_back('(');
   ret.append(DnsPacket::DnsNameToString(name_));
   ret.append(", ");
   ret.append(DnsPacket::TypeToString(ntohs(type_)));
   ret.append(", ");
   ret.append(DnsPacket::ClassToString(ntohs(clz_)));
   ret.push_back(')');

   return ret;
}
