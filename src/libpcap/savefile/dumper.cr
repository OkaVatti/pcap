# Wrapper for a `pcap_dumper_t*` – used to write packets to a savefile.
#
# Provides RAII resource management and a clean Crystal interface.
require "../lib/lib_pcap"
require "../error/error"

module LibPcap
  # Exception raised when dumper operations fail.
  class DumperError < Error; end

  # Manages a pcap_dumper_t handle.
  class PcapDumper
    getter ptr : LibPcap::PcapDumperPtr
    @handle : PcapHandle # keep a reference to prevent GC

    # Open a dumper for the given capture handle and filename.
    #
    # Raises `DumperError` if the file cannot be opened.
    def self.open(handle : PcapHandle, filename : String)
      ptr = LibPcap::C.dump_open(handle.ptr, filename.to_unsafe)
      if ptr.null?
        err = String.new(LibPcap::C.geterr(handle.ptr))
        raise DumperError.new("Failed to open dump file '#{filename}'", err)
      end
      new(ptr, handle)
    end

    protected def initialize(@ptr : LibPcap::PcapDumperPtr, @handle : PcapHandle)
    end

    # Write a packet to the dump file.
    #
    # The packet is represented by its header (`PcapPkthdr`) and raw data.
    # This method matches the C `pcap_dump` signature.
    def dump(header : PcapPkthdr*, data : Bytes) : Nil
      LibPcap::C.dump(ptr.as(UInt8*), header, data.to_unsafe)
    end

    # Write a `Packet` object.
    def dump(packet : Packet) : Nil
      LibPcap::C.dump(ptr.as(UInt8*), packet.header_ptr, packet.data.to_unsafe)
    end

    # Flush the dump file (write buffered data to disk).
    def flush : Nil
      rc = LibPcap::C.dump_flush(@ptr)
      if rc != 0
        raise DumperError.new("Failed to flush dump file")
      end
    end

    # Returns the current file position (for seeking, rarely used).
    def ftell : Int64
      LibPcap::C.dump_ftell(@ptr)
    end

    # Close the dumper explicitly.
    def close : Nil
      if @ptr && !@ptr.null?
        LibPcap::C.dump_close(@ptr)
        @ptr = Pointer(LibPcap::PcapDumperT).null
      end
    end

    # Finalizer ensures the dumper is closed when garbage‑collected.
    def finalize
      close
    end
  end
end
