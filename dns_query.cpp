#include <arpa/inet.h>
#include <stdint.h>

#include <iostream>

#include "dns_packet.h"
#include "dns_query.h"

DnsQuery::DnsQuery(DnsPacket& packet) {
   name_ = packet.GetName();

   type_ = ntohs(*((uint16_t*) packet.cur_));
   clz_ = ntohs(*((uint16_t*) (packet.cur_ + 2)));

   packet.cur_ += 4;
}

DnsQuery::DnsQuery(std::string& name, int type, int clz)
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

void DnsQuery::Print() {
   std::cout << "Query:" << std::endl;
   std::cout << "   Name: " << name_ << std::endl;
   std::cout << "   Type: " << (int) type_ << std::endl;
   std::cout << "   Class: " << (int) clz_ << std::endl;
}
