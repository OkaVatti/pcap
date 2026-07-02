# UDP datagram header parser.
#
# Fixed 8‑byte header; no options.
# All fields are in network byte order (big‑endian).
module LibPcap
  # Exception raised when UDP header parsing fails.
  class UDPParseError < Error; end

  class UDPHeader
    # Fixed UDP header length (8 bytes).
    HEADER_LEN = 8

    getter raw : Bytes

    # Creates a new UDPHeader from the given raw bytes.
    #
    # Raises `UDPParseError` if the data is too short.
    def initialize(data : Bytes)
      if data.size < HEADER_LEN
        raise UDPParseError.new("UDP header too short: #{data.size} bytes (need #{HEADER_LEN})")
      end
      @raw = data[0, HEADER_LEN]
    end

    # Source port.
    def src_port : UInt16
      (@raw[0].to_u16 << 8) | @raw[1].to_u16
    end

    # Destination port.
    def dst_port : UInt16
      (@raw[2].to_u16 << 8) | @raw[3].to_u16
    end

    # Length of UDP header + payload in bytes.
    def length : UInt16
      (@raw[4].to_u16 << 8) | @raw[5].to_u16
    end

    # Checksum.
    def checksum : UInt16
      (@raw[6].to_u16 << 8) | @raw[7].to_u16
    end

    # Returns the payload (everything after the 8‑byte header).
    def payload : Bytes
      @raw[HEADER_LEN..]
    end

    # ------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------

    # Returns a human‑readable description.
    def to_s(io : IO) : Nil
      io << "UDP " << src_port << " -> " << dst_port
      io << " len=" << length
    end
  end
end
