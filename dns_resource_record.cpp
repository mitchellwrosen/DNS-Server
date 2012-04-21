#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>

#include "dns_resource_record.h"
#include "dns_packet.h"

DnsResourceRecord::DnsResourceRecord(DnsPacket& packet) {
   name_ = packet.GetName();
   type_ = *((uint16_t*) packet.cur_);
   clz_ = *((uint16_t*) (packet.cur_ + 2));
   ttl_ = *((uint32_t*) (packet.cur_ + 4));
   data_len_ = *((uint16_t*) (packet.cur_ + 8));
   
   data_ = (char*) malloc((size_t) data_len_);
   if (!data_) {
      std::cerr << "Malloc failed." << std::endl;
      exit(EXIT_FAILURE);
   }
   memcpy(data_, packet.cur_ + 10, (size_t) data_len_);
   
   packet.cur_ += 10 + data_len_; 
}

DnsResourceRecord::~DnsResourceRecord() {
   free(data_);
}

void DnsResourceRecord::Print() {
   std::cout << "Resource Record:" << std::endl;
   std::cout << "   Name: %s" << name_ << std::endl;
   std::cout << "   Type: %d" << ntohs(type_) << std::endl;
   std::cout << "   Class: %d" << ntohs(clz_) << std::endl;
   std::cout << "   TTL: %d" << ntohl(ttl_) << std::endl;
   std::cout << "   Data length: %d" << ntohs(data_len_) << std::endl;
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
