#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include "dns_packet.h"

namespace {

// DNSPacket
const int kIdOffset = 0;
const int kFlagsOffset = 2;
const int kQueriesOffset = 4;
const int kAnswerRrsOffset = 6;
const int kAuthorityRrsOffset = 8;
const int kAdditionalRrsOffset = 10;
const int kFirstRecordOffset = 12;

// DNSPacket::Query
const int kQueryTypeOffset = 1;
const int kQueryClassOffset = 3;
const int kQueryNextRecordOffset = 5;

} // namespace

// DNSPacket
DNSPacket::DNSPacket(char* data)
      : data_(data),
        cur_(data + kFirstRecordOffset),
        cur_record_num(0),
        cur_record_(DNSPacket::Query(*this, cur_)),
        id_(ntohs(data[kIdOffset])),
        flags_(data[kFlagsOffset]),
        queries_(ntohs(data[kQueriesOffset])),
        answer_rrs_(ntohs(data[kAnswerRrsOffset])),
        authority_rrs_(ntohs(data[kAuthorityRrsOffset])),
        additional_rrs_(ntohs(data[kAdditionalRrsOffset])) {
}

uint16_t DNSPacket::id() {
   return htons((uint16_t) data_[kIdOffset]);
}

uint16_t DNSPacket::flags() {
   return (uint16_t) data_[kFlagsOffset];
}

uint16_t DNSPacket::queries() {
   return htons((uint16_t) data_[kQueriesOffset])
}

uint16_t DNSPacket::answer_rrs() {
   return htons((uint16_t) data_[kAnswerRrsOffset]);
}

uint16_t DNSPacket::authority_rrs() {
   return htons((uint16_t) data_[kAuthorityRrsOffset]);
}

uint16_t DNSPacket::additional_rrs() {
   return htons((uint16_t) data_[kAdditionalRrsOffset]);
}

// DNSPacket::Record
DNSPacket::Record::Record(const DNSPacket& packet) : packet_(packet) {
}

const DNSPacket::Record& DNSPacket::Record::operator++() {
}

// DNSPacket::Query
DNSPacket::Query::Query(const DNSPacket& packet)
      : Record(packet, data) {
   name_ = data;
   name_len_ = strlen(name_);
   type_ = ntohs(Record::packet_.cur_[name_len_ + kQueryTypeOffset]);
   clz_ = ntohs(Record::packet_.cur_[name_len_ + kQueryClassOffset]);
}

const DNSPacket::Record& DNSPacket::Query::operator++() {
   Record::packet_.cur_ += name_len_ + kQueryNextRecordOffset;

   // Determine if the next Record is a Query or ResourceRecord
   if (cur_record_num_ < queries_ - 1) {
      return cur_record_(Query(Record::packet_));
   } else {
      return cur_record_(DNSPacket::ResourceRecord(Record::packet_));
   }
}

// DNSPacket::ResourceRecord
DNSPacket::ResourceRecord* DNSPacket::ResourceRecord::operator++() {
   char* cur = cur();


   cur_ += ((DNSPacket::ResourceRecord*) cur_)->len +
         sizeof(DNSPacket::ResourceRecord::Header);
   return (DNSPacket::ResourceRecord*) cur_;
}

// DNSPacket::ResourceRecord::Header
