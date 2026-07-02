# Callback types used by libpcap functions.
#
# `pcap_loop` and `pcap_dispatch` accept a C function pointer with the signature:
#   void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
#
# We define a Crystal `Proc` that matches this ABI.
module LibPcap
  # Low‑level callback type – matches the C signature exactly.
  # - `user` is an opaque pointer (we usually box a Crystal block inside it).
  # - `header` points to the packet metadata.
  # - `data` points to the raw packet bytes.
  alias PcapHandler = (UInt8*, PcapPkthdr*, UInt8*) -> Void

  # High‑level Crystal callback – used internally when we wrap C callbacks.
  # This is not exposed to the C library; it's for our own `Box`‑ing logic.
  alias CrystalPacketHandler = (PcapPkthdr*, Bytes) -> Void
end
