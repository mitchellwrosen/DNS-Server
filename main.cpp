#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>

#include "debug.h"
#include "checksum.h"
#include "smartalloc.h"

#include "dns_packet.h"
#include "dns_server.h"

DnsServer* server;

void sigint_handler(int signum);

int main(int argc, char** argv) {
   // check for root
   if (getuid() || geteuid()) {
      fprintf(stderr, "Must be root to run %s\n", argv[0]);
      exit(EXIT_FAILURE);
   }

   // set up signal handling
   struct sigaction sigact;
   memset(&sigact, 0, sizeof(struct sigaction));
   sigact.sa_handler = sigint_handler;
   SYSCALL(sigaction(SIGINT, &sigact, NULL), "sigaction");

   server = new DnsServer();
   server->Run();
}

void sigint_handler(int signum) {
   switch (signum) {
      case SIGINT:
         close(server->sock());
         delete server;

         fprintf(stdout, "Server exiting cleanly.\n");
         exit(EXIT_FAILURE);
         break;
   }
}
