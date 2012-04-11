
class Server {
  public:
  protected:
   // Initialize server (get sock, bind, listen)
   Init(int port, struct addrinfo* hints, int backlog,
         void (*sighandler)(int) handler);

   int port_;
   int sock_;
   void (*sighandler)(int) handler_;
   int backlog_;


}
