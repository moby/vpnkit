let max_ip_datagram_length = 65535

(* IP datagram (65535) - IP header(20) - UDP header(8) *)
let max_udp_length = max_ip_datagram_length - 20 - 8

let max_mtu = 16424

let mib = 1024 * 1024
