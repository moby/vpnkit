(** A simple thread-per-socket AF_UNIX SOCK_DRAM send/recv implementation to work around
    the lack of support in libuv.
    
    This will be used for a single ethernet socket at a time, so scalability isn't required.
    *)

include Sig.UNIX_DGRAM
include Sig.CONN with type flow := flow
