#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "debug.h"

#include "dns_packet.h"

#define PORT "5003"

namespace constants = dns_packet_constants;

int main() {
   int sock;
   struct addrinfo hints, *servinfo, *p;

   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_DGRAM;

   int rv;
   if ((rv = getaddrinfo("localhost", PORT, &hints, &servinfo)) != 0) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
      return EXIT_FAILURE;
   }

   for (p = servinfo; p != NULL; p = p->ai_next) {
      if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
         perror("socket");
         continue;
      }
      break;
   }

   if (!p) {
      fprintf(stderr, "failed to bind socket\n");
      exit(EXIT_FAILURE);
   }

   char buf[512];
   const char* name = "\x03\x77\x77\x77\x03\x63\x73\x63\x07\x63\x61\x6c\x70\x6f\x6c\x79\x03\x65\x64\x75";
   char* p2 = DnsPacket::ConstructQuery(buf,
                                        htons(1234),   // id
                                        constants::opcode::Query,
                                        true,  // rd
                                        name,
                                        htons(constants::type::A),
                                        htons(constants::clz::IN));

   SYSCALL(sendto(sock, buf, p2-buf, 0, p->ai_addr, p->ai_addrlen), "sendto");
   freeaddrinfo(servinfo);

   fprintf(stdout, "Send %d bytes\n", p2-buf);
   close(sock);

   return EXIT_SUCCESS;
}
