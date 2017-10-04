#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/custom.h>
#include <caml/callback.h>
#include <caml/alloc.h>
#include <caml/unixsupport.h>

#include <stdio.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <NTSecAPI.h>
#else
#include <sys/socket.h>
#endif

CAMLprim value stub_get_SOMAXCONN(value unit){
  fprintf(stderr, "SOMAXCONN = %d\n", SOMAXCONN);
  return (Val_int (SOMAXCONN));
}

#if 0
#define Val_none Val_int(0)

CAMLprim value stub_RtlGenRandom(value len){
  CAMLparam1(len);
  CAMLlocal3(ret, some, str);
  ret = Val_none;
#ifdef WIN32
  /* Allocate an OCaml string of the required length and zero it so we
     never return garbage and think it's random */
  int c_len = Int_val(len);
  str = caml_alloc_string(c_len);
  ZeroMemory(String_val(str), c_len);

  if (!RtlGenRandom((PVOID)(String_val(str)), c_len)) {
    fprintf(stderr, "RtlGenRandom failed with %d\n", GetLastError());
    win32_maperr(GetLastError());
    unix_error(errno, "RtlGenRandom", Nothing);
  }
  some = caml_alloc(1, 0);
  Store_field(some, 0, str);
  ret = some;
#endif
  CAMLreturn(ret);
}
#endif
