# Ethernet frame header (14 bytes).
#
# Fields are in network byte order (big‑endian).
module LibPcap
  # Wrapper providing convenience methods for Ethernet headers.
  class EthernetHeader
    getter data : Bytes

    def initialize(data : Bytes)
      if data.size < 14
        raise Error.new("Ethernet header too short: #{data.size} bytes")
      end
      @data = data
    end

    # Destination MAC as a colon‑separated hex string.
    def dst_mac : String
      mac_to_s(@data[0, 6])
    end

    # Source MAC as a colon‑separated hex string.
    def src_mac : String
      mac_to_s(@data[6, 6])
    end

    # Ethertype as an integer.
    def ethertype : UInt16
      (@data[12].to_u16 << 8) | @data[13].to_u16
    end

    # Payload (everything after the 14‑byte header).
    def payload : Bytes
      @data[14..]
    end

    private def mac_to_s(bytes : Bytes) : String
      bytes.map { |b| b.to_s(16).rjust(2, '0') }.join(":")
    end
  end
end
