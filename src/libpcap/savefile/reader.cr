# High‑level reader for offline capture files.
#
# Provides an iterator‑style interface over packets in a pcap file.
require "../capture/handle"
require "../packet/packet"

module LibPcap
  class SavefileReader
    getter handle : PcapHandle

    # Open a savefile for reading.
    #
    # Raises `OpenError` if the file cannot be opened.
    def initialize(path : String)
      @handle = PcapHandle.for_offline(path)
    end

    # Iterate over all packets in the file, yielding each as a `Packet`.
    #
    # Example:
    #   reader.each_packet do |packet|
    #     puts packet.len
    #   end
    def each_packet(&block : Packet -> _) : Nil
      loop do
        result = @handle.next_packet
        case result
        when .ok?
          packet = result.value.as(Packet)
          block.call(packet)
        when .eof?
          break
        when .error?
          raise result.error.as(Error)
        end
      end
    end

    # Close the underlying handle.
    def close : Nil
      @handle.close
    end
  end
end
