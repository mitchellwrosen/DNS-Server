

void Server::Init(const std::string port, struct addrinfo* hints) {
   struct addrinfo info;
   struct addrinfo* server_info;
   struct addrinfo* p;
   int yes = 1;
   int ret;

   // get server addr info
   if ((ret = getaddrinfo(NULL, port, hints, &servinfo))) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
      exit(EXIT_FAILURE);
   }

   // bind to first available socket
   for (p = servinfo; p != NULL; p = p->ai_next) {
      if (-1 == (sock_ = socket(p->ai_family, p->ai_socktype,
            p->ai_protocol))) {
         perror("socket");
         continue;
      }

      SYSCALL(setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &yes,
            sizeof(int)));

      if (-1 == bind(sock_, p->ai_addr, p->ai_addrlen)) {
         close(sock_);
         perror("bind");
         continue;
      }

      freeaddrinfo(servinfo);
      break;
   }

   if (p == NULL) {
      fprintf(stderr, "Failed to bind.\n");
      exit(EXIT_FAILURE);
   }
}
