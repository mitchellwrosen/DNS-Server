#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>

#include "debug.h"

#include "dns_resource_record.h"
#include "dns_packet.h"

namespace constants = dns_packet_constants;

DnsResourceRecord::DnsResourceRecord(DnsPacket& packet) {
   name_ = packet.GetName();
   type_ = *((uint16_t*) packet.cur_);
   clz_ = *((uint16_t*) (packet.cur_ + 2));
   ttl_ = *((uint32_t*) (packet.cur_ + 4));
   data_len_ = *((uint16_t*) (packet.cur_ + 8));

   packet.cur_ += 10;

   // Special packets: NS, CNAME, PTR; MX; SOA
   uint16_t type = ntohs(type_);
   if (type == constants::type::NS ||
       type == constants::type::CNAME ||
       type == constants::type::PTR) {
      // Grab string
      std::string temp_str = packet.GetName();
      const char* temp_c_str = temp_str.c_str();

      MALLOCCHECK((data_ = (char*) malloc(strlen(temp_c_str)+1)));

      memcpy(data_, temp_c_str, strlen(temp_c_str)+1);
   }

   else if (type == constants::type::MX) {
      // Save a pointer to the preference and point packet to beginning of
      // exchange.
      char* p = packet.cur_;
      packet.cur_ += 2;
      std::string temp_str = packet.GetName();
      const char* temp_c_str = temp_str.c_str();

      MALLOCCHECK((data_ = (char*) malloc(2 + strlen(temp_c_str)+1)));

      memcpy(data_, p, 2);
      memcpy(data_ + 2, temp_c_str, strlen(temp_c_str)+1);
   } else if (type == constants::type::SOA) {
      // Grab both strings
      std::string temp_str1 = packet.GetName();
      std::string temp_str2 = packet.GetName();
      const char* temp_c_str1 = temp_str1.c_str();
      const char* temp_c_str2 = temp_str2.c_str();

      MALLOCCHECK((data_ = (char*) malloc(strlen(temp_c_str1)+1 +
                                          strlen(temp_c_str2)+1)));

      memcpy(data_,
             temp_c_str1,
             strlen(temp_c_str1)+1);

      memcpy(data_ + strlen(temp_c_str1)+1,
             temp_c_str2,
             strlen(temp_c_str2)+1);

      memcpy(data_ + strlen(temp_c_str1)+1 + strlen(temp_c_str2)+1,
             packet.cur_,
             4);

      memcpy(data_ + strlen(temp_c_str1)+1 + strlen(temp_c_str2)+1 + 4,
             packet.cur_ + 4,
             4);

      memcpy(data_ + strlen(temp_c_str1)+1 + strlen(temp_c_str2)+1 + 8,
             packet.cur_ + 8,
             4);

      memcpy(data_ + strlen(temp_c_str1)+1 + strlen(temp_c_str2)+1 + 12,
             packet.cur_ + 12,
             4);
   } else {
      MALLOCCHECK((data_ = (char*) malloc((size_t) ntohs(data_len_))));
      memcpy(data_, packet.cur_, ntohs(data_len_));
   }

}

DnsResourceRecord::DnsResourceRecord(std::string name, uint16_t type,
      uint16_t clz, uint32_t ttl, uint16_t data_len, char* data)
      : name_(name), type_(type), clz_(clz), ttl_(ttl), data_len_(data_len) {
   MALLOCCHECK((data_ = (char*) malloc((size_t) ntohs(data_len_))));
   memcpy(data_, data, ntohs(data_len_));
}

DnsResourceRecord::DnsResourceRecord(const DnsResourceRecord& rr)
      : name_(rr.name_), type_(rr.type_), clz_(rr.clz_), ttl_(rr.ttl_),
      data_len_(rr.data_len_) {
   MALLOCCHECK((data_ = (char*) malloc((size_t) data_len_)));
   memcpy(data_, rr.data_, data_len_);
}

DnsResourceRecord::~DnsResourceRecord() {
   free(data_);
}

DnsResourceRecord& DnsResourceRecord::operator=(const DnsResourceRecord& rr) {
   if (this == &rr)
      return *this;

   name_ = rr.name_;
   type_ = rr.type_;
   clz_ = rr.clz_;
   ttl_ = rr.ttl_;
   data_len_ = rr.data_len_;

   MALLOCCHECK((data_ = (char*) malloc((size_t) data_len_)));
   memcpy(data_, rr.data_, data_len_);
   return *this;
}

bool DnsResourceRecord::operator<(const DnsResourceRecord& record) const {
   if (name_ != record.name_)
      return name_ < record.name_;

   if (type_ != record.type_)
      return type_ < record.type_;

   if (clz_ != record.clz_)
      return clz_ < record.clz_;

   if (ttl_ != record.ttl_)
      return ttl_ < record.ttl_;

   if (data_len_ != record.data_len_)
      return data_len_ < record.data_len_;

   for (int i = 0; i < data_len_; ++i)
      if (data_[i] != record.data_[i])
         return data_[i] < record.data_[i];

   return false;
}

DnsQuery DnsResourceRecord::ConstructQuery() const {
   return DnsQuery(name_, type_, clz_);
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
