# The main capture handle.
#
# Wraps a `pcap_t*` and provides:
#   - RAII resource management (automatic `pcap_close` via finalizer)
#   - Configuration (snaplen, promiscuous mode, timeout, buffer size)
#   - Packet capture via `#loop` (with Crystal block) and `#next_packet`
#   - BPF filter application
#   - Statistics
#   - Error translation into `LibPcap::Error` exceptions
require "./device"
require "../error/error"
require "../lib/lib_pcap"

module LibPcap
  class PcapHandle
    getter ptr : LibPcap::PcapPtr
    @callback_box : Pointer(Void)? # holds the boxed proc while looping

    # Create a handle for a live capture on a given device.
    #
    # Raises `OpenError` if the device cannot be opened.
    # The handle is not activated until `#activate` is called.
    def self.for_live(device : Device | String)
      errbuf = Bytes.new(PCAP_ERRBUF_SIZE)
      dev_name = device.is_a?(Device) ? device.name : device
      ptr = LibPcap::C.create(dev_name.to_unsafe, errbuf)
      if ptr.null?
        raise OpenError.new("Failed to create pcap handle for '#{dev_name}'", String.new(errbuf))
      end
      new(ptr)
    end

    # Open an offline savefile (pcap or pcapng).
    #
    # Raises `OpenError` if the file cannot be opened.
    def self.for_offline(path : String)
      errbuf = Bytes.new(PCAP_ERRBUF_SIZE)
      ptr = LibPcap::C.open_offline(path.to_unsafe, errbuf)
      if ptr.null?
        raise OpenError.new("Failed to open savefile '#{path}'", String.new(errbuf))
      end
      new(ptr)
    end

    # Open an offline savefile with specified timestamp precision.
    # Precision should be PCAP_TSTAMP_PRECISION_MICRO or PCAP_TSTAMP_PRECISION_NANO.
    def self.for_offline_with_precision(path : String, precision : Int32)
      errbuf = Bytes.new(PCAP_ERRBUF_SIZE)
      ptr = LibPcap::C.open_offline_with_tstamp_precision(path.to_unsafe, precision, errbuf)
      if ptr.null?
        raise OpenError.new("Failed to open savefile '#{path}' with precision #{precision}", String.new(errbuf))
      end
      new(ptr)
    end

    # Internal: wraps an already‑acquired C pointer.
    # The pointer must be non‑null.
    protected def initialize(@ptr : LibPcap::PcapPtr)
    end

    # ------------------------------------------------------------
    # Configuration (must be called *before* `#activate`)
    # ------------------------------------------------------------

    def snaplen=(value : Int)
      check_cfg LibPcap::C.set_snaplen(@ptr, value.to_i32)
    end

    def promisc=(on : Bool)
      check_cfg LibPcap::C.set_promisc(@ptr, on ? 1 : 0)
    end

    def timeout_ms=(ms : Int)
      check_cfg LibPcap::C.set_timeout(@ptr, ms.to_i32)
    end

    def buffer_size=(bytes : Int)
      check_cfg LibPcap::C.set_buffer_size(@ptr, bytes.to_i32)
    end

    def immediate_mode=(on : Bool)
      check_cfg LibPcap::C.set_immediate_mode(@ptr, on ? 1 : 0)
    end

    def rfmon=(on : Bool)
      check_cfg LibPcap::C.set_rfmon(@ptr, on ? 1 : 0)
    end

    # ------------------------------------------------------------
    # Activation
    # ------------------------------------------------------------

    # Activates the capture handle.
    # Must be called before any capture operation.
    #
    # Raises `ActivationError` on failure.
    def activate : Nil
      rc = LibPcap::C.activate(@ptr)
      unless rc == 0
        err = String.new(LibPcap::C.geterr(@ptr))
        raise ActivationError.new("pcap_activate failed with code #{rc}", err)
      end
    end

    # Is the handle active? (non‑zero snapshot length usually indicates active)
    def active? : Bool
      LibPcap::C.get_snaplen(@ptr) > 0
    end

    # ------------------------------------------------------------
    # BPF Filter
    # ------------------------------------------------------------

    # Compile and set a BPF filter expression.
    #
    # Example: handle.filter = "tcp port 80"
    def filter=(expression : String)
      # netmask 0 lets libpcap figure it out (or use 0xFFFFFFFF for no mask)
      prog = LibPcap::BpfProgram.new
      rc = LibPcap::C.compile(@ptr, pointerof(prog), expression.to_unsafe, 1, 0_u32)
      if rc != 0
        err = String.new(LibPcap::C.geterr(@ptr))
        raise FilterError.new("Failed to compile filter '#{expression}'", err)
      end

      rc = LibPcap::C.setfilter(@ptr, pointerof(prog))
      LibPcap::C.freecode(pointerof(prog)) # free even if setfilter fails

      if rc != 0
        err = String.new(LibPcap::C.geterr(@ptr))
        raise FilterError.new("Failed to set filter '#{expression}'", err)
      end
    end

    # ------------------------------------------------------------
    # Packet Capture – Callback‑based Loop
    # ------------------------------------------------------------

    # Capture packets in a loop, yielding each packet to the given block.
    #
    # - `count` : number of packets to capture (0 = infinite until `#breakloop`)
    # - Yields a `Packet` for each captured packet.
    # - Raises `BreakLoopError` if `#breakloop` is called from within the block.
    # - Raises `Error` on other libpcap errors.
    #
    # Example:
    #   handle.loop do |packet|
    #     puts packet.data.size
    #   end
    def loop(count : Int = 0, &block : Packet -> _) : Nil
      boxed = Box.box(->(hdr : LibPcap::PcapPkthdr*, bytes : Bytes) {
        packet = Packet.new(hdr, bytes)
        block.call(packet)
      })

      # Keep the box alive for the duration of the loop.
      @callback_box = boxed.as(Pointer(Void))

      # The C callback trampoline.
      callback = ->(user : UInt8*, hdr : LibPcap::PcapPkthdr*, data : UInt8*) {
        box = Box(LibPcap::CrystalPacketHandler).unbox(user.as(Void*))
        bytes = Bytes.new(data, hdr.value.caplen)
        box.call(hdr, bytes)
      }

      rc = LibPcap::C.loop(@ptr, count.to_i32, callback, @callback_box.not_nil!.as(UInt8*)) # ameba:disable Lint/NotNil

      # Clear the box reference after the loop ends.
      @callback_box = nil

      case rc
      when 0
        # Normal completion (count reached)
        nil
      when -1
        err = String.new(LibPcap::C.geterr(@ptr))
        raise Error.new("pcap_loop failed", err)
      when -2
        # Loop was broken by `pcap_breakloop`
        raise BreakLoopError.new
      else
        raise Error.new("pcap_loop returned unexpected code #{rc}")
      end
    end

    # ------------------------------------------------------------
    # Single‑Packet Retrieval (non‑callback)
    # ------------------------------------------------------------

    # Fetch the next available packet (blocking).
    #
    # Returns a `Result(Packet)` where:
    #   - `.ok?`   : packet is available
    #   - `.eof?`  : end‑of‑file (offline capture only)
    #   - `.error?` : an error occurred (the error is stored inside)
    #
    # This is the preferred method for single‑packet processing.
    def next_packet : Result(Packet)
      hdr_ptr = Pointer(LibPcap::PcapPkthdr).null
      data_ptr = Pointer(UInt8).null
      rc = LibPcap::C.next_ex(@ptr, pointerof(hdr_ptr), pointerof(data_ptr))

      case rc
      when PCAP_NEXT_EX_OK
        caplen = hdr_ptr.value.caplen
        packet = Packet.new(hdr_ptr, Bytes.new(data_ptr, caplen))
        Result(Packet).ok(packet)
      when PCAP_NEXT_EX_EOF
        Result(Packet).eof
      when PCAP_NEXT_EX_ERROR
        err = String.new(LibPcap::C.geterr(@ptr))
        Result(Packet).error(Error.new("pcap_next_ex failed", err))
      when -2 # Some libpcap versions return PCAP_ERROR_BREAK at EOF
        Result(Packet).eof
      else
        Result(Packet).error(Error.new("pcap_next_ex returned unexpected code #{rc}"))
      end
    end

    # ------------------------------------------------------------
    # Interrupt the loop
    # ------------------------------------------------------------

    # Break an ongoing `#loop` from another thread or signal handler.
    #
    # The running `#loop` will raise `BreakLoopError`.
    def breakloop : Nil
      LibPcap::C.breakloop(@ptr)
    end

    # ------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------

    # Returns a tuple of (received, dropped, if_dropped).
    #
    # Raises `Error` if `pcap_stats` fails.
    def stats : {UInt32, UInt32, UInt32}
      stat = LibPcap::PcapStat.new
      rc = LibPcap::C.stats(@ptr, pointerof(stat))
      if rc != 0
        err = String.new(LibPcap::C.geterr(@ptr))
        raise Error.new("pcap_stats failed", err)
      end
      {stat.ps_recv, stat.ps_drop, stat.ps_ifdrop}
    end

    # ------------------------------------------------------------
    # Datalink type helpers
    # ------------------------------------------------------------

    # Returns the current datalink type (DLT_* constant).
    def datalink : Int32
      LibPcap::C.get_datalink(@ptr).to_i32
    end

    # Set the datalink type (if supported by the capture).
    def datalink=(dlt : Int32)
      rc = LibPcap::C.set_datalink(@ptr, dlt)
      if rc != 0
        err = String.new(LibPcap::C.geterr(@ptr))
        raise ConfigurationError.new("Failed to set datalink to #{dlt}", err)
      end
    end

    # Human‑readable name for the current datalink.
    def datalink_name : String
      name = LibPcap::C.datalink_val_to_name(datalink)
      name.null? ? "unknown" : String.new(name)
    end

    # ------------------------------------------------------------
    # Resource Management
    # ------------------------------------------------------------

    # Explicitly close the handle and release all resources.
    # The handle cannot be used afterwards.
    def close : Nil
      if @ptr && !@ptr.null?
        LibPcap::C.close(@ptr)
        @ptr = Pointer(LibPcap::PcapT).null
        # The callback box is no longer needed; GC will collect it.
        @callback_box = nil
      end
    end

    # Create a "dead" handle (for writing to savefiles without capturing).
    # The datalink type must match the packets you will write.
    def self.dead(datalink : Int32, snaplen : Int32 = 65535) : self
      ptr = LibPcap::C.open_dead(datalink.to_i32, snaplen.to_i32)
      if ptr.null?
        raise OpenError.new("Failed to create dead pcap handle")
      end
      new(ptr)
    end

    # Finalizer ensures the handle is closed when the object is GC'd.
    def finalize
      close
    end

    # ------------------------------------------------------------
    # Timestamp precision
    # ------------------------------------------------------------

    # Set timestamp precision (microseconds or nanoseconds).
    # Must be called before activation.
    def tstamp_precision=(precision : Int32)
      check_cfg LibPcap::C.set_tstamp_precision(@ptr, precision)
    end

    # Get the current timestamp precision.
    def tstamp_precision : Int32
      LibPcap::C.get_tstamp_precision(@ptr)
    end

    # ------------------------------------------------------------
    # Non‑blocking mode
    # ------------------------------------------------------------

    # Enable or disable non‑blocking mode.
    def nonblock=(on : Bool)
      errbuf = Bytes.new(PCAP_ERRBUF_SIZE)
      rc = LibPcap::C.setnonblock(@ptr, on ? 1 : 0, errbuf)
      if rc != 0
        raise Error.new("Failed to set non‑blocking mode", String.new(errbuf))
      end
    end

    # Check if non‑blocking mode is enabled.
    def nonblock? : Bool
      errbuf = Bytes.new(PCAP_ERRBUF_SIZE)
      rc = LibPcap::C.getnonblock(@ptr, errbuf)
      if rc == -1
        raise Error.new("Failed to get non‑blocking mode", String.new(errbuf))
      end
      rc == 1
    end

    # Get the file descriptor for select/poll (only works in some cases).
    def selectable_fd : Int32?
      fd = LibPcap::C.get_selectable_fd(@ptr)
      fd == -1 ? nil : fd
    end

    # ------------------------------------------------------------
    # Direction control
    # ------------------------------------------------------------

    # Set the direction of captured packets (incoming/outgoing/both).
    # Must be called after activation.
    def direction=(dir : Int32)
      rc = LibPcap::C.setdirection(@ptr, dir)
      if rc != 0
        err = String.new(LibPcap::C.geterr(@ptr))
        raise ConfigurationError.new("Failed to set direction", err)
      end
    end

    # ------------------------------------------------------------
    # List of datalink types
    # ------------------------------------------------------------

    # Returns an array of DLT_* values supported by the device.
    def datalink_types : Array(Int32)
      dlt_list = Pointer(Int32).null
      count = LibPcap::C.list_datalinks(@ptr, pointerof(dlt_list))
      if count < 0
        err = String.new(LibPcap::C.geterr(@ptr))
        raise Error.new("Failed to list datalink types", err)
      end
      types = Array(Int32).new(count) { |i| dlt_list[i] }
      LibPcap::C.free_datalinks(dlt_list)
      types
    end

    # ------------------------------------------------------------
    # Packet injection
    # ------------------------------------------------------------

    # Inject a raw packet (Bytes) onto the network.
    # Returns the number of bytes sent, or raises on error.
    def inject(data : Bytes) : Int32
      sent = LibPcap::C.inject(@ptr, data.to_unsafe, data.size)
      if sent == -1
        err = String.new(LibPcap::C.geterr(@ptr))
        raise Error.new("Failed to inject packet", err)
      end
      sent.to_i32
    end

    # Alias for #inject (compatibility with libpcap naming)
    def sendpacket(data : Bytes) : Int32
      inject(data)
    end

    # ------------------------------------------------------------
    # Dispatch (alternative to loop)
    # ------------------------------------------------------------

    # Capture up to `count` packets using `pcap_dispatch`.
    # This is similar to `#loop` but returns immediately after processing
    # available packets (or after timeout) without waiting for the full count.
    # Yields each packet.
    def dispatch(count : Int = -1, &block : Packet -> _) : Nil
      boxed = Box.box(->(hdr : LibPcap::PcapPkthdr*, bytes : Bytes) {
        packet = Packet.new(hdr, bytes)
        block.call(packet)
      })

      callback = ->(user : UInt8*, hdr : LibPcap::PcapPkthdr*, data : UInt8*) {
        box = Box(LibPcap::CrystalPacketHandler).unbox(user.as(Void*))
        bytes = Bytes.new(data, hdr.value.caplen)
        box.call(hdr, bytes)
      }

      rc = LibPcap::C.dispatch(@ptr, count.to_i32, callback, boxed.as(UInt8*))
      # The box is not kept, but the callback runs synchronously; we don't need to store it.
      case rc
      when 0
        # No packets read (timeout or no packets)
        nil
      when -1
        err = String.new(LibPcap::C.geterr(@ptr))
        raise Error.new("pcap_dispatch failed", err)
      else
        # rc is the number of packets processed
        nil
      end
    end

    # ------------------------------------------------------------
    # Remote capture (using pcap_open)
    # ------------------------------------------------------------
    {% if flag?(:remote) %}
      # Open a remote capture session.
      # The source string should be in the form "rpcap://host:port/interface"
      # or "rpcaps://..." for TLS.
      # Returns a new handle (already activated).
      def self.for_remote(
        source : String,
        snaplen : Int32 = 65535,
        flags : Int32 = 0,
        read_timeout : Int32 = 1000,
        auth_type : Int32 = 0, # PCAP_RMTAUTH_NULL or PCAP_RMTAUTH_PWD
        username : String? = nil,
        password : String? = nil,
      ) : self
        errbuf = Bytes.new(PCAP_ERRBUF_SIZE)
        auth_ptr = Pointer(LibPcap::PcapRmtauth).null

        if username || password
          auth_struct = LibPcap::PcapRmtauth.new(
            type: auth_type,
            username: username ? username.to_unsafe : Pointer(UInt8).null,
            password: password ? password.to_unsafe : Pointer(UInt8).null
          )
          auth_ptr = pointerof(auth_struct)
        end

        ptr = LibPcap::C.open(
          source.to_unsafe,
          snaplen,
          flags,
          read_timeout,
          auth_ptr,
          errbuf
        )
        if ptr.null?
          raise OpenError.new("Failed to open remote capture '#{source}'", String.new(errbuf))
        end
        new(ptr)
      end
    {% end %}

    # ------------------------------------------------------------
    # Timestamp type selection
    # ------------------------------------------------------------

    # Set the timestamp type (must be called before activation).
    # Raises ConfigurationError if the type is not supported.
    def tstamp_type=(type : Int32)
      rc = LibPcap::C.set_tstamp_type(@ptr, type)
      if rc != 0
        err = String.new(LibPcap::C.geterr(@ptr))
        raise ConfigurationError.new("Failed to set timestamp type to #{type}", err)
      end
    end

    # List all timestamp types supported by this capture device.
    # Returns an array of constants (PCAP_TSTAMP_*).
    def tstamp_types : Array(Int32)
      types_ptr = Pointer(Int32).null
      count = LibPcap::C.list_tstamp_types(@ptr, pointerof(types_ptr))
      if count < 0
        err = String.new(LibPcap::C.geterr(@ptr))
        raise Error.new("Failed to list timestamp types", err)
      end
      types = Array(Int32).new(count) { |i| types_ptr[i] }
      LibPcap::C.free_tstamp_types(types_ptr)
      types
    end

    # ------------------------------------------------------------
    # Protocol setting (Linux‑specific) – optional
    # ------------------------------------------------------------
    {% if flag?(:protocol) %}
      # Set the packet protocol (only relevant for certain link‑layer types).
      # Must be called before activation.
      def protocol=(proto : Int32)
        rc = LibPcap::C.set_protocol(@ptr, proto)
        if rc != 0
          err = String.new(LibPcap::C.geterr(@ptr))
          raise ConfigurationError.new("Failed to set protocol to #{proto}", err)
        end
      end
    {% end %}

    # ------------------------------------------------------------
    # Extended dump open (append mode)
    # ------------------------------------------------------------

    # Open a dumper in append mode (if supported by libpcap).
    # Writes packets to the end of an existing file.
    # Raises DumperError on failure.
    def open_dumper_append(filename : String) : PcapDumper
      ptr = LibPcap::C.dump_open_append(@ptr, filename.to_unsafe)
      if ptr.null?
        err = String.new(LibPcap::C.geterr(@ptr))
        raise DumperError.new("Failed to open dump file in append mode '#{filename}'", err)
      end
      PcapDumper.new(ptr, self)
    end

    # ------------------------------------------------------------
    # Status to string (utility, class method)
    # ------------------------------------------------------------

    # Convert a libpcap error code to a human‑readable string.
    def self.statustostr(error : Int32) : String
      ptr = LibPcap::C.statustostr(error)
      ptr.null? ? "Unknown error" : String.new(ptr)
    end

    # ------------------------------------------------------------
    # Open a regular dumper (convenience, already existed via SavefileWriter)
    # But we also provide a direct method for flexibility.
    # ------------------------------------------------------------

    # Open a dumper for writing a savefile.
    # The returned PcapDumper must be closed by the caller.
    def open_dumper(filename : String) : PcapDumper
      ptr = LibPcap::C.dump_open(@ptr, filename.to_unsafe)
      if ptr.null?
        err = String.new(LibPcap::C.geterr(@ptr))
        raise DumperError.new("Failed to open dump file '#{filename}'", err)
      end
      PcapDumper.new(ptr, self)
    end

    # ------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------

    private def check_cfg(rc : Int32) : Nil
      if rc != 0
        err = String.new(LibPcap::C.geterr(@ptr))
        raise ConfigurationError.new("Configuration failed with code #{rc}", err)
      end
    end
  end
end
