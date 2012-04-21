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
   
   data_ = (char*) malloc((size_t) ntohs(data_len_));
   if (!data_) {
      std::cerr << "Malloc failed." << std::endl;
      exit(EXIT_FAILURE);
   }
   memcpy(data_, packet.cur_ + 10, (size_t) ntohs(data_len_));
   
   packet.cur_ += 10 + data_len_; 
}

DnsResourceRecord::DnsResourceRecord(std::string name, uint16_t type, 
      uint16_t clz, uint32_t ttl, uint16_t data_len, char* data) 
      : name_(name), type_(type), clz_(clz), ttl_(ttl), data_len_(data_len) {
   data_ = (char*) malloc((size_t) ntohs(data_len_));
   if (!data_) {
      std::cerr << "Malloc failed." << std::endl;
      exit(EXIT_FAILURE);
   }
   memcpy(data_, data, (size_t) ntohs(data_len_));
}

DnsResourceRecord::DnsResourceRecord(const DnsResourceRecord& rr)
      : name_(rr.name_), type_(rr.type_), clz_(rr.clz_), ttl_(rr.ttl_),
      data_len_(rr.data_len_) {
   data_ = (char*) malloc((size_t) ntohs(data_len_));
   if (!data_) {
      std::cerr << "Malloc failed." << std::endl;
      exit(EXIT_FAILURE);
   }
   memcpy(data_, rr.data_, (size_t) ntohs(data_len_));
}

DnsResourceRecord::~DnsResourceRecord() {
   free(data_);
}

void DnsResourceRecord::Print() {
   std::cout << "Resource Record:" << std::endl;
   std::cout << "   Name: " << name_ << std::endl;
   std::cout << "   Type: " << ntohs(type_) << std::endl;
   std::cout << "   Class: " << ntohs(clz_) << std::endl;
   std::cout << "   TTL: " << ntohl(ttl_) << std::endl;
   std::cout << "   Data length: " << ntohs(data_len_) << std::endl;
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
