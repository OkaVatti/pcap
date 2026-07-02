# High‑level savefile writer.
#
# Wraps a `PcapDumper` and provides an easy way to write packets from a capture session.
require "./dumper"
require "../capture/handle"
require "../packet/packet"

module LibPcap
  class SavefileWriter
    getter dumper : PcapDumper
    getter handle : PcapHandle

    # Create a new writer for the given handle and output filename.
    #
    # The handle must be already activated (or offline).
    def initialize(@handle : PcapHandle, filename : String)
      @dumper = PcapDumper.open(@handle, filename)
    end

    # Write a single packet (either a `Packet` object or separate header/data).
    def write(packet : Packet) : Nil
      @dumper.dump(packet)
    end

    # Write a packet from raw header and data.
    def write(header : LibPcap::PcapPkthdr, data : Bytes) : Nil
      @dumper.dump(pointerof(header), data)
    end

    # Convenience: capture packets and write them to the file.
    # The block receives the packet and should return `true` to continue, `false` to stop.
    #
    # Example:
    #   writer.capture_loop(count: 100) do |packet|
    #     puts packet.len
    #     true
    #   end
    def capture_loop(count : Int = 0, &block : Packet -> Bool) : Nil
      begin
        @handle.loop(count: count) do |packet|
          @dumper.dump(packet)
          unless block.call(packet)
            @handle.breakloop
            next # exit the block; the C loop will see breakloop and stop
          end
        end
      rescue BreakLoopError
        # Expected early exit when breakloop was called; ignore.
      end
    end

    # Close the writer and the underlying dumper.
    def close : Nil
      @dumper.close
    end
  end
end
