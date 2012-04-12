#ifndef _SERVER_H_
#define _SERVER_H_

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

#include "checksum.h"
#include "smartalloc.h"

class Server {
  public:
   // Initialize the server (get sock, bind, listen).
   void Init(const std::string port, struct addrinfo* hints);

   // Performs a select on the specified socket for the specified amount of
   // time.
   bool HasDataToRead(int sock, int seconds, int useconds);

   //virtual void Send() = 0;
   //virtual void Receive() = 0;
   virtual void Run() = 0;

  protected:
   int sock_;
   int backlog_;
};

#endif   // _SERVER_H_
