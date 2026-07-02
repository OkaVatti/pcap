# IPv4 packet header parser.
#
# Handles the fixed 20‑byte header plus optional options.
# All fields are in network byte order (big‑endian).
module LibPcap
  # Exception raised when IPv4 header parsing fails.
  class IPv4ParseError < Error; end

  class IPv4Header
    # Minimum header length without options (20 bytes).
    MIN_HEADER_LEN = 20

    getter raw : Bytes
    @header_len : Int32
    @options_offset : Int32
    @payload_offset : Int32

    # Creates a new IPv4Header from the given raw bytes.
    #
    # Raises `IPv4ParseError` if the data is too short or malformed.
    def initialize(data : Bytes)
      if data.size < MIN_HEADER_LEN
        raise IPv4ParseError.new("IPv4 header too short: #{data.size} bytes (need #{MIN_HEADER_LEN})")
      end

      @raw = data

      # Parse header length (IHL) in 32‑bit words.
      ihl = (data[0] & 0x0F).to_i32
      header_len = ihl * 4
      if header_len < MIN_HEADER_LEN
        raise IPv4ParseError.new("Invalid IPv4 header length: #{header_len} bytes")
      end
      if data.size < header_len
        raise IPv4ParseError.new("IPv4 header data too short: #{data.size} bytes (need #{header_len})")
      end

      @header_len = header_len
      @options_offset = MIN_HEADER_LEN
      @payload_offset = header_len
    end

    # ------------------------------------------------------------
    # Fixed header fields (first 20 bytes)
    # ------------------------------------------------------------

    # Version (should be 4 for IPv4).
    def version : UInt8
      (@raw[0] >> 4) & 0x0F
    end

    # Header length in bytes (including options).
    def header_len : Int32
      @header_len
    end

    # Type of Service (DSCP + ECN).
    def tos : UInt8
      @raw[1]
    end

    # Total length of the IPv4 packet (header + payload) in bytes.
    def total_len : UInt16
      (@raw[2].to_u16 << 8) | @raw[3].to_u16
    end

    # Identification field (used for fragmentation).
    def id : UInt16
      (@raw[4].to_u16 << 8) | @raw[5].to_u16
    end

    # Flags and fragment offset (combined 16‑bit value).
    # Bits 0‑2: flags (Reserved, DF, MF), bits 3‑15: fragment offset.
    def flags_fragment : UInt16
      (@raw[6].to_u16 << 8) | @raw[7].to_u16
    end

    # Don't Fragment flag.
    def df? : Bool
      (flags_fragment & 0x4000) != 0
    end

    # More Fragments flag.
    def mf? : Bool
      (flags_fragment & 0x2000) != 0
    end

    # Fragment offset (in 8‑byte units).
    def fragment_offset : UInt16
      flags_fragment & 0x1FFF
    end

    # Time to Live.
    def ttl : UInt8
      @raw[8]
    end

    # Protocol number (e.g., 6 = TCP, 17 = UDP, 1 = ICMP).
    def protocol : UInt8
      @raw[9]
    end

    # Header checksum.
    def checksum : UInt16
      (@raw[10].to_u16 << 8) | @raw[11].to_u16
    end

    # Source IP address as a 32‑bit integer (network byte order).
    def src_ip_raw : UInt32
      (@raw[12].to_u32 << 24) | (@raw[13].to_u32 << 16) |
        (@raw[14].to_u32 << 8) | @raw[15].to_u32
    end

    # Destination IP address as a 32‑bit integer (network byte order).
    def dst_ip_raw : UInt32
      (@raw[16].to_u32 << 24) | (@raw[17].to_u32 << 16) |
        (@raw[18].to_u32 << 8) | @raw[19].to_u32
    end

    # Source IP address as a dotted‑decimal string.
    def src_ip : String
      ip_to_s(@raw[12, 4])
    end

    # Destination IP address as a dotted‑decimal string.
    def dst_ip : String
      ip_to_s(@raw[16, 4])
    end

    # ------------------------------------------------------------
    # Options (variable‑length)
    # ------------------------------------------------------------

    # Returns the raw bytes of the options (empty if none).
    def options : Bytes
      @raw[@options_offset, @header_len - MIN_HEADER_LEN]
    end

    # Iterates over each option.
    # Each option is a tuple `{type, len, data}` where `len` includes the type and len bytes.
    # See RFC 791 for option definitions.
    def each_option(&)
      pos = @options_offset
      while pos < @header_len
        type = @raw[pos]
        if type == 0 # End of Options List
          break
        elsif type == 1 # No Operation (NOP)
          pos += 1
          next
        else
          # Options have a length field (type + len + data)
          if pos + 1 >= @header_len
            break
          end
          len = @raw[pos + 1].to_i32
          if len < 2 || pos + len > @header_len
            break
          end
          yield type, len, @raw[pos, len]
          pos += len
        end
      end
    end

    # ------------------------------------------------------------
    # Payload
    # ------------------------------------------------------------

    # Returns the payload (everything after the header, including options).
    def payload : Bytes
      @raw[@payload_offset..]
    end

    # ------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------

    # Returns a human‑readable description.
    def to_s(io : IO) : Nil
      io << "IPv4 " << src_ip << " -> " << dst_ip
      io << " proto=" << protocol
      io << " len=" << total_len
    end

    # FIXED: correctly formats an IP address from four bytes.
    private def ip_to_s(bytes : Bytes) : String
      bytes.join('.')
    end
  end
end
