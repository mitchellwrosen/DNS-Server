#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "debug.h"
#include "server.h"

#include "checksum.h"
#include "smartalloc.h"


void Server::Init(const std::string port, struct addrinfo* hints) {
   struct addrinfo* info;
   struct addrinfo* p;
   int yes = 1;
   int ret;

   // get server addr info
   if ((ret = getaddrinfo(NULL, port.c_str(), hints, &info))) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
      exit(EXIT_FAILURE);
   }

   // bind to first available socket
   for (p = info; p != NULL; p = p->ai_next) {
      if (-1 == (sock_ = socket(p->ai_family, p->ai_socktype,
            p->ai_protocol))) {
         perror("socket");
         continue;
      }

      SYSCALL(setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &yes,
            sizeof(int)), "setsockopt");

      if (-1 == bind(sock_, p->ai_addr, p->ai_addrlen)) {
         close(sock_);
         perror("bind");
         continue;
      }

      freeaddrinfo(info);
      break;
   }

   if (p == NULL) {
      fprintf(stderr, "Failed to bind.\n");
      exit(EXIT_FAILURE);
   }
}

bool Server::HasDataToRead(int sock, int seconds, int useconds) {
   struct timeval tv;

   tv.tv_sec = seconds;
   tv.tv_usec = useconds;

   return HasDataToRead(sock, &tv);
}

bool Server::HasDataToRead(int sock) {
   return HasDataToRead(sock, NULL);
}

bool Server::HasDataToRead(int sock, struct timeval* tv) {
   fd_set readfds;

   FD_ZERO(&readfds);
   FD_SET(sock, &readfds);

   SYSCALL(select(sock + 1, &readfds, NULL, NULL, tv), "select");

   if (FD_ISSET(sock, &readfds))
      return true;
   else
      return false;
}
