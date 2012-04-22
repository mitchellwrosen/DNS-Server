#ifndef _DEBUG_H_
#define _DEBUG_H_

// Error on NULL
#define MALLOCCHECK(arg); {\
   if (!arg) {\
      std::cerr << "Malloc failed." << std::endl;\
      exit(EXIT_FAILURE);\
   }\
}

// For system calls that set errno and return non-zero on error
#define SYSCALL(call, msg); {\
   if (call < 0) {\
      perror(msg);\
      exit(EXIT_FAILURE);\
   }\
}

// For system calls that set errno and return non-zero on error
// Allows cleanup of one file descriptor
#define SYSCALL_FD1(call, fd, msg); {\
   if (call < 0) {\
      perror(msg);\
      close(fd);\
      exit(EXIT_FAILURE);\
   }\
}

#define LOGGING true

#define LOG if (LOGGING) std::cout

#endif   // _DEBUG_H_
