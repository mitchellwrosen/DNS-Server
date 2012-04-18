#include <stdint.h>

#include "dns_packet.h"
#include "dns_query.h"

DnsQuery::DnsQuery(char* data) {
   name_ = DnsPacket::GetString(&data);
   type_ = ntohs(*((uint16_t*) data));
   clz_ = ntohs(*((uint16_t*) (data + 2)));
}
