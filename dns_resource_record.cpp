#include <arpa/inet.h>
#include <stdint.h>

#include <iostream>

#include "dns_resource_record.h"
#include "dns_packet.h"

DnsResourceRecord::DnsResourceRecord(char* packet, char* rr) {
   name_ = DnsPacket::GetName(packet, &rr);
   type_ = ntohs(*((uint16_t*) rr));
   clz_ = ntohs(*((uint16_t*) (rr + 2)));
   ttl_ = ntohl(*((uint32_t*) (rr + 4)));
   data_len_ = ntohs(*((uint16_t*) (rr + 8)));
   data_ = rr + 10;
}

void DnsResourceRecord::Print() {
   std::cout << "Resource Record:" << std::endl;
   std::cout << "   Name: %s" << name_ << std::endl;
   std::cout << "   Type: %d" << type_ << std::endl;
   std::cout << "   Class: %d" << clz_ << std::endl;
   std::cout << "   TTL: %d" << ttl_ << std::endl;
   std::cout << "   Data length: %d" << data_len_ << std::endl;
   std::cout << "   Data:  ";
   PrintData(10);
}

void DnsResourceRecord::PrintData(int cutoff) {
   int i;
   for (i = 0; i < (cutoff < data_len_ ? cutoff : data_len_); ++i)
      std::cout << data_[i];

   if (i == cutoff)
      std::cout << "..." << std::endl;
   else
      std::cout << std::endl;
}
