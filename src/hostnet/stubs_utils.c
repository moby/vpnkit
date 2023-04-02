#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/custom.h>
#include <caml/callback.h>
#include <caml/alloc.h>
#include <caml/unixsupport.h>
#include <caml/bigarray.h>
#include <caml/threads.h>

#include <stdio.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <NTSecAPI.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#endif

CAMLprim value stub_get_SOMAXCONN(value unit){
  return (Val_int (SOMAXCONN));
}


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
    win32_maperr(GetLastError());
    unix_error(errno, "RtlGenRandom", Nothing);
  }
  some = caml_alloc(1, 0);
  Store_field(some, 0, str);
  ret = some;
#endif
  CAMLreturn(ret);
}

CAMLprim value stub_setSocketTTL(value s, value ttl){
  CAMLparam2(s, ttl);
  int c_ttl = Int_val(ttl);
#ifdef WIN32
  SOCKET c_s = Socket_val(s);
  if (setsockopt(c_s, IPPROTO_IP, IP_TTL, (const char *)&c_ttl, sizeof(c_ttl)) != 0) {
    win32_maperr(GetLastError());
#else
  int c_fd = Int_val(s);
  if (setsockopt(c_fd, IPPROTO_IP, IP_TTL, &c_ttl, sizeof(c_ttl)) != 0) {
#endif
    unix_error(errno, "setsockopt", Nothing);
  }
  CAMLreturn(Val_unit);
}

CAMLprim value stub_cstruct_send(value val_fd, value val_buf, value val_ofs, value val_len) {
  CAMLparam4(val_fd, val_buf, val_ofs, val_len);
#ifdef WIN32
  caml_failwith("stub_cstruct_send not implemented on Win32");
#endif
  int fd = Int_val(val_fd);
  const char *buf = (char*)Caml_ba_data_val(val_buf) + Long_val(val_ofs);
  size_t len = (size_t) Long_val(val_len);
  caml_release_runtime_system();
  ssize_t n = send(fd, buf, len, 0);
  caml_acquire_runtime_system();
  if (n < 0) unix_error(errno, "send", Nothing);
  CAMLreturn(Val_int(n));
}

CAMLprim value stub_cstruct_recv(value val_fd, value val_buf, value val_ofs, value val_len) {
  CAMLparam4(val_fd, val_buf, val_ofs, val_len);
#ifdef WIN32
  caml_failwith("stub_cstruct_recv not implemented on Win32");
#endif
  int fd = Int_val(val_fd);
  void *buf = (void*)Caml_ba_data_val(val_buf) + Long_val(val_ofs);
  size_t len = (size_t) Long_val(val_len);
  caml_release_runtime_system();
  ssize_t n = recv(fd, buf, len, 0);
  caml_acquire_runtime_system();
  if (n < 0) unix_error(errno, "recv", Nothing);
  CAMLreturn(Val_int(n));
}