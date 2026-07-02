# The primary `lib` block that links against `libpcap`.
#
# Every public libpcap function we intend to use is declared here.
# We follow the naming convention: C function `pcap_foo` becomes `foo`.
# (This makes high‑level wrappers read more naturally.)
require "./lib_pcap/constants"
require "./lib_pcap/structs"
require "./lib_pcap/callbacks"

module LibPcap
  @[Link("pcap")]
  lib C
    # ------------------------------------------------------------
    # Initialization & version
    # ------------------------------------------------------------
    fun init = pcap_init(opt : LibC::Int) : LibC::Int
    fun lib_version = pcap_lib_version : UInt8*

    # ------------------------------------------------------------
    # Device enumeration
    # ------------------------------------------------------------
    fun findalldevs = pcap_findalldevs(alldevsp : PcapIf**, errbuf : UInt8*) : LibC::Int
    fun freealldevs = pcap_freealldevs(devs : PcapIf*) : Void

    # ------------------------------------------------------------
    # Handle creation & activation
    # ------------------------------------------------------------
    fun create = pcap_create(source : UInt8*, errbuf : UInt8*) : PcapT*
    fun activate = pcap_activate(p : PcapT*) : LibC::Int

    # Configuration (setters)
    fun set_snaplen = pcap_set_snaplen(p : PcapT*, snaplen : LibC::Int) : LibC::Int
    fun set_promisc = pcap_set_promisc(p : PcapT*, mode : LibC::Int) : LibC::Int
    fun set_timeout = pcap_set_timeout(p : PcapT*, to_ms : LibC::Int) : LibC::Int
    fun set_buffer_size = pcap_set_buffer_size(p : PcapT*, size : LibC::Int) : LibC::Int
    fun set_immediate_mode = pcap_set_immediate_mode(p : PcapT*, mode : LibC::Int) : LibC::Int
    fun set_rfmon = pcap_set_rfmon(p : PcapT*, mode : LibC::Int) : LibC::Int

    # Getters (status)
    fun get_snaplen = pcap_snapshot(p : PcapT*) : LibC::Int
    fun get_datalink = pcap_datalink(p : PcapT*) : LibC::Int
    fun set_datalink = pcap_set_datalink(p : PcapT*, dlt : LibC::Int) : LibC::Int

    # ------------------------------------------------------------
    # Packet capture – callback & single‑packet
    # ------------------------------------------------------------
    fun loop = pcap_loop(p : PcapT*, cnt : LibC::Int, callback : PcapHandler, user : UInt8*) : LibC::Int
    fun dispatch = pcap_dispatch(p : PcapT*, cnt : LibC::Int, callback : PcapHandler, user : UInt8*) : LibC::Int
    fun next = pcap_next(p : PcapT*, h : PcapPkthdr*) : UInt8*
    fun next_ex = pcap_next_ex(p : PcapT*, h : PcapPkthdr**, data : UInt8**) : LibC::Int
    fun breakloop = pcap_breakloop(p : PcapT*) : Void

    # ------------------------------------------------------------
    # BPF filters
    # ------------------------------------------------------------
    fun compile = pcap_compile(p : PcapT*, fp : BpfProgram*, filter : UInt8*, optimize : LibC::Int, netmask : UInt32) : LibC::Int
    fun setfilter = pcap_setfilter(p : PcapT*, fp : BpfProgram*) : LibC::Int
    fun freecode = pcap_freecode(fp : BpfProgram*) : Void

    # ------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------
    fun stats = pcap_stats(p : PcapT*, stats : PcapStat*) : LibC::Int

    # ------------------------------------------------------------
    # Savefile (offline) operations
    # ------------------------------------------------------------
    fun open_offline = pcap_open_offline(fname : UInt8*, errbuf : UInt8*) : PcapT*
    fun open_offline_with_tstamp_precision = pcap_open_offline_with_tstamp_precision(
      fname : UInt8*, precision : LibC::Int, errbuf : UInt8*,
    ) : PcapT*

    # Dead handle creation
    fun open_dead = pcap_open_dead(datalink : LibC::Int, snaplen : LibC::Int) : PcapT*

    fun dump_open = pcap_dump_open(p : PcapT*, fname : UInt8*) : PcapDumperT*
    fun dump = pcap_dump(user : UInt8*, h : PcapPkthdr*, data : UInt8*) : Void
    fun dump_close = pcap_dump_close(p : PcapDumperT*) : Void
    fun dump_ftell = pcap_dump_ftell(p : PcapDumperT*) : Int64

    # ------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------
    fun geterr = pcap_geterr(p : PcapT*) : UInt8*
    fun perror = pcap_perror(p : PcapT*, prefix : UInt8*) : Void
    fun strerror = pcap_strerror(error : LibC::Int) : UInt8*

    # ------------------------------------------------------------
    # Miscellaneous utilities
    # ------------------------------------------------------------
    fun lookupnet = pcap_lookupnet(device : UInt8*, netp : UInt32*, maskp : UInt32*, errbuf : UInt8*) : LibC::Int
    fun datalink_val_to_name = pcap_datalink_val_to_name(dlt : LibC::Int) : UInt8*
    fun datalink_val_to_description = pcap_datalink_val_to_description(dlt : LibC::Int) : UInt8*
    fun datalink_name_to_val = pcap_datalink_name_to_val(name : UInt8*) : LibC::Int

    # ------------------------------------------------------------
    # Close / free
    # ------------------------------------------------------------
    fun close = pcap_close(p : PcapT*) : Void

    # ------------------------------------------------------------
    # Timestamp precision
    # ------------------------------------------------------------
    fun set_tstamp_precision = pcap_set_tstamp_precision(p : PcapT*, precision : LibC::Int) : LibC::Int
    fun get_tstamp_precision = pcap_get_tstamp_precision(p : PcapT*) : LibC::Int

    # ------------------------------------------------------------
    # Timestamp types
    # ------------------------------------------------------------
    fun set_tstamp_type = pcap_set_tstamp_type(p : PcapT*, tstamp_type : LibC::Int) : LibC::Int
    fun list_tstamp_types = pcap_list_tstamp_types(p : PcapT*, tstamp_types : Int32**) : LibC::Int
    fun free_tstamp_types = pcap_free_tstamp_types(tstamp_types : Int32*) : Void

    # ------------------------------------------------------------
    # Protocol (Linux‑specific) – optional, guarded by -D protocol
    # ------------------------------------------------------------
    {% if flag?(:protocol) %}
      fun set_protocol = pcap_set_protocol(p : PcapT*, protocol : LibC::Int) : LibC::Int
    {% end %}

    # ------------------------------------------------------------
    # Dump open append (if libpcap supports it; available from version 1.9.0)
    # ------------------------------------------------------------
    fun dump_open_append = pcap_dump_open_append(p : PcapT*, fname : UInt8*) : PcapDumperT*

    # ------------------------------------------------------------
    # Status to string
    # ------------------------------------------------------------
    fun statustostr = pcap_statustostr(error : LibC::Int) : UInt8*

    # ------------------------------------------------------------
    # Non-blocking mode
    # ------------------------------------------------------------
    fun setnonblock = pcap_setnonblock(p : PcapT*, mode : LibC::Int, errbuf : UInt8*) : LibC::Int
    fun getnonblock = pcap_getnonblock(p : PcapT*, errbuf : UInt8*) : LibC::Int
    fun get_selectable_fd = pcap_get_selectable_fd(p : PcapT*) : LibC::Int

    # ------------------------------------------------------------
    # Direction control
    # ------------------------------------------------------------
    fun setdirection = pcap_setdirection(p : PcapT*, direction : LibC::Int) : LibC::Int

    # ------------------------------------------------------------
    # List of datalink types
    # ------------------------------------------------------------
    fun list_datalinks = pcap_list_datalinks(p : PcapT*, dlt_list : Int32**) : LibC::Int
    fun free_datalinks = pcap_free_datalinks(dlt_list : Int32*) : Void

    # ------------------------------------------------------------
    # Dump flush
    # ------------------------------------------------------------
    fun dump_flush = pcap_dump_flush(p : PcapDumperT*) : LibC::Int

    # ------------------------------------------------------------
    # Packet injection
    # ------------------------------------------------------------
    fun inject = pcap_inject(p : PcapT*, data : UInt8*, size : LibC::SizeT) : LibC::Int
    # Alias for sendpacket (same signature)
    fun sendpacket = pcap_sendpacket(p : PcapT*, data : UInt8*, size : LibC::Int) : LibC::Int

    {% if flag?(:remote) %}
      # ------------------------------------------------------------
      # Remote capture (pcap_open)
      # ------------------------------------------------------------
      fun open = pcap_open(source : UInt8*, snaplen : LibC::Int, flags : LibC::Int, read_timeout : LibC::Int, auth : PcapRmtauth*, errbuf : UInt8*) : PcapT*
    {% end %}

    # ------------------------------------------------------------
    # Dispatch (alternative to loop) – already declared above as `dispatch`
    # ------------------------------------------------------------
  end

  # Low‑level pointer aliases for use in high‑level classes.
  # These are now in the module scope, so they are LibPcap::PcapPtr etc.
  alias PcapPtr = PcapT*
  alias PcapDumperPtr = PcapDumperT*
end
