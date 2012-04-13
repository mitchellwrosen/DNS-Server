#include <stdint.h>

#include "dns_packet.h"

// DNSPacket
DNSPacket::DNSPacket(char* data) : data_(data) { }

const int DNSPacket::kIdOffset = 0;
const int DNSPacket::kFlagsOffset = 2;
const int DNSPacket::kQueriesOffset = 4;
const int DNSPacket::kAnswerRrsOffset = 6;
const int DNSPacket::kAuthorityRrsOffset = 8;
const int DNSPacket::kAdditionalRrsOffset = 10;

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

// DNSPacket::Query


// DNSPacket::ResourceRecord
DNSPacket::ResourceRecord* DNSPacket::ResourceRecord::operator++() {
   char* cur = cur();


   cur_ += ((DNSPacket::ResourceRecord*) cur_)->len +
         sizeof(DNSPacket::ResourceRecord::Header);
   return (DNSPacket::ResourceRecord*) cur_;
}

// DNSPacket::ResourceRecord::Header
