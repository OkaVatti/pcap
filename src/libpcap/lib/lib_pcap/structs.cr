# Extern (C‑compatible) structs used by libpcap.
#
# These map directly to the C structures defined in <pcap.h>.
# We use `@[Extern]` to ensure the exact memory layout.
module LibPcap
  # Packet header returned by `pcap_next_ex` and callbacks.
  @[Extern]
  struct PcapPkthdr
    property ts : LibC::Timeval
    property caplen : UInt32
    property len : UInt32

    # Zero‑initialized header (all fields 0).
    def initialize
      @ts = LibC::Timeval.new
      @caplen = 0_u32
      @len = 0_u32
    end

    # Header with explicit values.
    def initialize(ts : LibC::Timeval, caplen : UInt32, len : UInt32)
      @ts = ts
      @caplen = caplen
      @len = len
    end
  end

  # Network interface address – linked list.
  @[Extern]
  struct PcapAddr
    getter next_addr : PcapAddr*  # next address in list (C field name: "next")
    getter addr : LibC::Sockaddr* # pointer to `struct sockaddr`
    getter netmask : LibC::Sockaddr*
    getter broadaddr : LibC::Sockaddr*
    getter dstaddr : LibC::Sockaddr*

    def initialize
      @next_addr = Pointer(PcapAddr).null
      @addr = Pointer(LibC::Sockaddr).null
      @netmask = Pointer(LibC::Sockaddr).null
      @broadaddr = Pointer(LibC::Sockaddr).null
      @dstaddr = Pointer(LibC::Sockaddr).null
    end
  end

  # Network interface description – linked list.
  @[Extern]
  struct PcapIf
    getter next_if : PcapIf*    # next interface (C field name: "next")
    getter name : UInt8*        # interface name (e.g. "eth0")
    getter description : UInt8* # human‑readable description (may be NULL)
    getter addresses : PcapAddr*
    getter flags : UInt32 # interface flags (IFF_*)

    def initialize
      @next_if = Pointer(PcapIf).null
      @name = Pointer(UInt8).null
      @description = Pointer(UInt8).null
      @addresses = Pointer(PcapAddr).null
      @flags = 0_u32
    end
  end

  # BPF program structure – used for filters.
  @[Extern]
  struct BpfProgram
    getter bf_len : UInt32     # number of BPF instructions
    getter bf_insns : BpfInsn* # pointer to instruction array

    def initialize
      @bf_len = 0_u32
      @bf_insns = Pointer(BpfInsn).null
    end
  end

  # BPF instruction (internal, rarely used directly).
  @[Extern]
  struct BpfInsn
    getter code : UInt16
    getter jt : UInt8
    getter jf : UInt8
    getter k : UInt32

    def initialize
      @code = 0_u16
      @jt = 0_u8
      @jf = 0_u8
      @k = 0_u32
    end
  end

  # Statistics returned by `pcap_stats`.
  @[Extern]
  struct PcapStat
    getter ps_recv : UInt32   # number of packets received
    getter ps_drop : UInt32   # number of packets dropped
    getter ps_ifdrop : UInt32 # drops by the network interface (not always supported)

    def initialize
      @ps_recv = 0_u32
      @ps_drop = 0_u32
      @ps_ifdrop = 0_u32
    end
  end

  # Opaque handle types – we need non‑empty structs for Crystal 1.20.2+.
  # The dummy fields ensure the struct is not empty; we only use pointers,
  # so the actual size is irrelevant.
  @[Extern]
  struct PcapT
    @_dummy_pcap : UInt8

    def initialize
      @_dummy_pcap = 0_u8
    end
  end

  @[Extern]
  struct PcapDumperT
    @_dummy_dumper : UInt8

    def initialize
      @_dummy_dumper = 0_u8
    end
  end

  # Add after PcapDumperT

  # Remote authentication (used with pcap_open)
  @[Extern]
  struct PcapRmtauth
    getter type : Int32
    getter username : UInt8*
    getter password : UInt8*

    # We don't use the `auth` field in Crystal directly; we will use an alias.

    def initialize(@type : Int32, @username : UInt8*, @password : UInt8*)
    end
  end

  # Additional timestamp precision getter (we already have constants)
end
