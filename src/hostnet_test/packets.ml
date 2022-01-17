

let icmp_echo_request ~id ~seq ~len =
  let payload = Cstruct.create len in
  let pattern = "plz reply i'm so lonely" in
  for i = 0 to Cstruct.length payload - 1 do
    Cstruct.set_char payload i pattern.[i mod (String.length pattern)]
  done;
  let req = Icmpv4_packet.({code = 0x00; ty = Icmpv4_wire.Echo_request;
                            subheader = Id_and_seq (id, seq)}) in
  let header = Icmpv4_packet.Marshal.make_cstruct req ~payload in
  Cstruct.concat [ header; payload ]
