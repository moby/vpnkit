#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/custom.h>
#include <caml/callback.h>
#include <caml/alloc.h>

#include <stdio.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

CAMLprim value stub_get_SOMAXCONN(){
  fprintf(stderr, "SOMAXCONN = %d\n", SOMAXCONN);
  return (Val_int (SOMAXCONN));
}
