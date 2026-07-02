# libpcap constants, error codes, and DLT_* values.
#
# All values are taken from <pcap.h>, <pcap/dlt.h>, <pcap/remote-ext.h>.
# Only the most commonly used constants are exposed here.
# Additional ones can be added as needed.
module LibPcap
  # Size of the error buffer used by libpcap functions.
  PCAP_ERRBUF_SIZE = 256

  # Promiscuous mode flag for `pcap_set_promisc`.
  PCAP_PROMISCUOUS = 1

  # Return values for `pcap_next_ex`
  PCAP_NEXT_EX_OK    =  1
  PCAP_NEXT_EX_EOF   =  0
  PCAP_NEXT_EX_ERROR = -1

  # Timeout value for `pcap_set_timeout` (milliseconds)
  PCAP_TIMEOUT_DEFAULT = 1000

  # Common Data Link Types (DLT_*)
  DLT_NULL        =   0
  DLT_EN10MB      =   1 # Ethernet (10/100/1000)
  DLT_EN3MB       =   2
  DLT_AX25        =   3
  DLT_PRONET      =   4
  DLT_CHAOS       =   5
  DLT_IEEE802     =   6 # Token Ring
  DLT_ARCNET      =   7
  DLT_SLIP        =   8
  DLT_PPP         =   9
  DLT_FDDI        =  10
  DLT_ATM_RFC1483 =  11
  DLT_RAW         =  12 # Raw IP
  DLT_SLIP_BSDOS  =  13
  DLT_PPP_BSDOS   =  14
  DLT_IEEE802_11  = 105 # 802.11 wireless
  DLT_LINUX_SLL   = 113 # Linux cooked capture
  DLT_IPV4        = 228
  DLT_IPV6        = 229
  DLT_MPLS        = 234

  # ------------------------------------------------------------
  # Remote capture flags (for `pcap_open`)
  # (taken from <pcap/remote-ext.h>)
  # ------------------------------------------------------------
  PCAP_OPENFLAG_PROMISCUOUS        =  1
  PCAP_OPENFLAG_DATATX_UDP         =  2
  PCAP_OPENFLAG_NOCAPTURE_RPCAP    =  4
  PCAP_OPENFLAG_NOCAPTURE_LOCAL    =  8
  PCAP_OPENFLAG_MAX_RESPONSIVENESS = 16

  # Remote authentication types
  PCAP_RMTAUTH_NULL = 0
  PCAP_RMTAUTH_PWD  = 1

  # ------------------------------------------------------------
  # Timestamp precision (for `pcap_set_tstamp_precision`)
  # ------------------------------------------------------------
  PCAP_TSTAMP_PRECISION_MICRO = 0
  PCAP_TSTAMP_PRECISION_NANO  = 1

  # ------------------------------------------------------------
  # Timestamp types (for `pcap_set_tstamp_type` and `pcap_list_tstamp_types`)
  # (from <pcap.h>)
  # ------------------------------------------------------------
  PCAP_TSTAMP_HOST             = 0 # host OS timestamp (microsecond resolution)
  PCAP_TSTAMP_HOST_LOWPREC     = 1 # host OS low‑precision timestamp (e.g., 10 ms)
  PCAP_TSTAMP_HOST_HIPREC      = 2 # host OS high‑precision (nanosecond, if available)
  PCAP_TSTAMP_ADAPTER          = 3 # adapter hardware timestamp (if available)
  PCAP_TSTAMP_ADAPTER_UNSYNCED = 4 # adapter timestamp not synced to system clock

  # ------------------------------------------------------------
  # Protocols for `pcap_set_protocol` (Linux‑specific, for DLT_LINUX_SLL2)
  # ------------------------------------------------------------
  PCAP_PROTOCOL_UNKNOWN    = 0
  PCAP_PROTOCOL_LINUX_SLL2 = 1 # use Linux SLL2 header
  PCAP_PROTOCOL_ETHERNET   = 2 # use Ethernet header (if available)

  # ------------------------------------------------------------
  # Direction (for `pcap_setdirection`)
  # ------------------------------------------------------------
  PCAP_D_IN    = 0
  PCAP_D_OUT   = 1
  PCAP_D_INOUT = 2
end
