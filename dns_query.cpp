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

void DnsQuery::Print() {
   std::cout << "Query:" << std::endl;
   std::cout << "   Name: %s" << name_ << std::endl;
   std::cout << "   Type: %d" << type_ << std::endl;
   std::cout << "   Class: %d" << clz_ << std::endl;
}
