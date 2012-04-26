#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
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

   // Skip over data_len_ (because we might ignore it), point cur_ at data
   packet.cur_ += 10;

   // Special packets: NS, CNAME, PTR; MX; SOA
   uint16_t type = ntohs(type_);
   if (type == constants::type::NS ||
       type == constants::type::CNAME ||
       type == constants::type::PTR) {
      // Grab string
      std::string temp_str = packet.GetName();
      const char* temp_c_str = temp_str.c_str();

      data_len_ = htons(strlen(temp_c_str)+1);
      MALLOCCHECK((data_ = (char*) malloc(ntohs(data_len_))));

      memcpy(data_, temp_c_str, ntohs(data_len_));
   } else if (type == constants::type::MX) {
      // Save a pointer to the preference and point packet to beginning of
      // exchange.
      char* p = packet.cur_;
      packet.cur_ += 2;
      std::string temp_str = packet.GetName();
      const char* temp_c_str = temp_str.c_str();

      data_len_ = htons(2 + strlen(temp_c_str)+1);
      MALLOCCHECK((data_ = (char*) malloc(ntohs(data_len_))));

      memcpy(data_, p, 2);
      memcpy(data_ + 2, temp_c_str, strlen(temp_c_str)+1);
   } else if (type == constants::type::SOA) {
      // Grab both strings
      std::string temp_str1 = packet.GetName();
      std::string temp_str2 = packet.GetName();
      const char* temp_c_str1 = temp_str1.c_str();
      const char* temp_c_str2 = temp_str2.c_str();

      data_len_ = htons(strlen(temp_c_str1)+1 + strlen(temp_c_str2)+1 + 16);
      MALLOCCHECK((data_ = (char*) malloc(ntohs(data_len_))));

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
      data_len_ = *((uint16_t*) (packet.cur_ - 2));

      MALLOCCHECK((data_ = (char*) malloc((size_t) ntohs(data_len_))));
      memcpy(data_, packet.cur_, ntohs(data_len_));

      packet.cur_ += ntohs(data_len_);
   }

}

DnsResourceRecord::DnsResourceRecord(std::string name, uint16_t type,
      uint16_t clz, uint32_t ttl, uint16_t data_len, char* data)
      : name_(name), type_(type), clz_(clz), ttl_(ttl), data_len_(data_len) {
   MALLOCCHECK((data_ = (char*) malloc((size_t) ntohs(data_len))));
   memcpy(data_, data, ntohs(data_len));
}

DnsResourceRecord::DnsResourceRecord(const DnsResourceRecord& rr)
      : name_(rr.name_), type_(rr.type_), clz_(rr.clz_), ttl_(rr.ttl_),
      data_len_(rr.data_len_) {
   MALLOCCHECK((data_ = (char*) malloc((size_t) ntohs(rr.data_len_))));
   memcpy(data_, rr.data_, ntohs(rr.data_len_));
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

   for (int i = 0; i < ntohs(data_len_); ++i) {
      if (data_[i] != record.data_[i])
         return data_[i] < record.data_[i];
   }

   return false;
}

char* DnsResourceRecord::Construct(char* packet, char* p) const {
   // Attempt to name-compress name
   const char* name_p = name_.c_str();

   p = ConstructDnsName(packet, p, name_p);

   // Write type, clz, ttl, data len
   memcpy(p, &type_, 2);
   memcpy(p + 2, &clz_, 2);
   memcpy(p + 4, &ttl_, 4);
   memcpy(p + 8, &data_len_, 2);
   p += 10;

   if (type_ == ntohs(constants::type::NS) ||
       type_ == ntohs(constants::type::CNAME) ||
       type_ == ntohs(constants::type::PTR)) {
      p = ConstructDnsName(packet, p, data_);
   } else if (type_ == ntohs(constants::type::MX)) {
      memcpy(p, &data_, 2); // preference
      p += 2;
      p = ConstructDnsName(packet, p, data_ + 2);
   } //else if (type_ == ntohs(constants::type::SOA)) {
      // TODO this bullshit
   //}
   else {
      memcpy(p, data_, ntohs(data_len_));
      p += ntohs(data_len_);
   }

   return p;
}

char* DnsResourceRecord::ConstructDnsName(
      char* packet, char* p, const char* name_p) const {
   char* pos;
   char* initial_p = p;

   // Keep trying increasingly small chunks of the name -- we'll be happy with
   // any compression at all
   while (*name_p) {
      pos = std::search(packet, initial_p, name_p,
            name_p + strlen(name_p)+1);

      // Substring found -- write the pointer at p
      if (pos != p) {
         int offset = pos - packet;
         offset |= 0xc000; // set first two bits
         offset = htons(offset);
         memcpy(p, &offset, 2);
         p += 2;
         break;
      } else {
         memcpy(p, name_p, *name_p + 1);
         p += *name_p + 1;
         name_p += *name_p + 1;
      }
   }

   return p;
}

DnsQuery DnsResourceRecord::ConstructQuery() const {
   return DnsQuery(name_, type_, clz_);
}

std::string DnsResourceRecord::ToString() const {
   std::string ret;

   ret.push_back('(');
   ret.append(DnsPacket::DnsNameToString(name_));
   ret.append(", ");
   ret.append(DnsPacket::TypeToString(ntohs(type_)));
   ret.append(", ");
   ret.append(DnsPacket::ClassToString(ntohs(clz_)));
   ret.append(", ");
   ret.append("ttl");//ntohl(ttl_));
   ret.append(", ");
   ret.append("data len");
   ret.append(", [");

   uint16_t type = ntohs(type_);
   if (type == constants::type::NS ||
       type == constants::type::PTR ||
       type == constants::type::CNAME) {
      ret.append(data_);
   } else if (type == constants::type::NS) {
      ret.append("pref, ");
      ret.append(data_ + 2);
   } else if (type == constants::type::SOA) {
      // TODO
      ret.append("SOA");
   } else {
      ret.append(data_, ntohs(data_len_));
   }

   ret.append("])");

   return ret;
}
