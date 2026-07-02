# TCP segment header parser.
#
# Handles the fixed 20‑byte header plus optional options.
# All fields are in network byte order (big‑endian).
module LibPcap
  # Exception raised when TCP header parsing fails.
  class TCPParseError < Error; end

  class TCPHeader
    # Minimum header length without options (20 bytes).
    MIN_HEADER_LEN = 20

    getter raw : Bytes
    @header_len : Int32
    @payload_offset : Int32

    # Creates a new TCPHeader from the given raw bytes.
    #
    # Raises `TCPParseError` if the data is too short or malformed.
    def initialize(data : Bytes)
      if data.size < MIN_HEADER_LEN
        raise TCPParseError.new("TCP header too short: #{data.size} bytes (need #{MIN_HEADER_LEN})")
      end

      @raw = data

      # Data Offset (number of 32‑bit words in header).
      data_offset = ((data[12] >> 4) & 0x0F).to_i32
      header_len = data_offset * 4
      if header_len < MIN_HEADER_LEN
        raise TCPParseError.new("Invalid TCP header length: #{header_len} bytes")
      end
      if data.size < header_len
        raise TCPParseError.new("TCP header data too short: #{data.size} bytes (need #{header_len})")
      end

      @header_len = header_len
      @payload_offset = header_len
    end

    # ------------------------------------------------------------
    # Fixed header fields (first 20 bytes)
    # ------------------------------------------------------------

    # Source port.
    def src_port : UInt16
      (@raw[0].to_u16 << 8) | @raw[1].to_u16
    end

    # Destination port.
    def dst_port : UInt16
      (@raw[2].to_u16 << 8) | @raw[3].to_u16
    end

    # Sequence number.
    def seq_num : UInt32
      (@raw[4].to_u32 << 24) | (@raw[5].to_u32 << 16) |
        (@raw[6].to_u32 << 8) | @raw[7].to_u32
    end

    # Acknowledgment number (valid if ACK flag is set).
    def ack_num : UInt32
      (@raw[8].to_u32 << 24) | (@raw[9].to_u32 << 16) |
        (@raw[10].to_u32 << 8) | @raw[11].to_u32
    end

    # Data Offset (header length in 32‑bit words).
    def data_offset : UInt8
      (@raw[12] >> 4) & 0x0F
    end

    # Header length in bytes (including options).
    def header_len : Int32
      @header_len
    end

    # Reserved bits (should be zero).
    def reserved : UInt8
      @raw[12] & 0x0F
    end

    # Flags byte (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN).
    # The lower 9 bits are flags.
    def flags : UInt16
      # Combine the 3 bits from byte 12 (reserved) with byte 13.
      ((@raw[12] & 0x0F).to_u16 << 8) | @raw[13].to_u16
    end

    # Individual flags (convenience predicates).
    def ns? : Bool
      (flags & 0x0100) != 0
    end

    def cwr? : Bool
      (flags & 0x0080) != 0
    end

    def ece? : Bool
      (flags & 0x0040) != 0
    end

    def urg? : Bool
      (flags & 0x0020) != 0
    end

    def ack? : Bool
      (flags & 0x0010) != 0
    end

    def psh? : Bool
      (flags & 0x0008) != 0
    end

    def rst? : Bool
      (flags & 0x0004) != 0
    end

    def syn? : Bool
      (flags & 0x0002) != 0
    end

    def fin? : Bool
      (flags & 0x0001) != 0
    end

    # Window size.
    def window : UInt16
      (@raw[14].to_u16 << 8) | @raw[15].to_u16
    end

    # Checksum.
    def checksum : UInt16
      (@raw[16].to_u16 << 8) | @raw[17].to_u16
    end

    # Urgent pointer (valid if URG flag is set).
    def urgent : UInt16
      (@raw[18].to_u16 << 8) | @raw[19].to_u16
    end

    # ------------------------------------------------------------
    # Options (variable‑length)
    # ------------------------------------------------------------

    # Returns the raw bytes of the options (empty if none).
    def options : Bytes
      @raw[MIN_HEADER_LEN, @header_len - MIN_HEADER_LEN]
    end

    # Iterates over each option.
    # Each option is a tuple `{kind, len, data}` where `len` includes the kind and len bytes.
    # See RFC 793 and others for option definitions.
    def each_option(&)
      pos = MIN_HEADER_LEN
      while pos < @header_len
        kind = @raw[pos]
        if kind == 0 # End of Option List
          break
        elsif kind == 1 # No Operation (NOP)
          pos += 1
          next
        else
          # Options have a length field (kind + len + data)
          if pos + 1 >= @header_len
            break
          end
          len = @raw[pos + 1].to_i32
          if len < 2 || pos + len > @header_len
            break
          end
          yield kind, len, @raw[pos, len]
          pos += len
        end
      end
    end

    # ------------------------------------------------------------
    # Payload
    # ------------------------------------------------------------

    # Returns the payload (TCP data) after the header, including options.
    def payload : Bytes
      @raw[@payload_offset..]
    end

    # ------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------

    # Returns a human‑readable description.
    # In `to_s`, change `|f|` to `|io|`
    def to_s(io : IO) : Nil
      io << "TCP " << src_port << " -> " << dst_port
      io << " seq=" << seq_num
      io << " ack=" << ack_num if ack?
      flags_str = String.build do |str|
        str << "SYN " if syn?
        str << "ACK " if ack?
        str << "FIN " if fin?
        str << "RST " if rst?
        str << "PSH " if psh?
        str << "URG " if urg?
      end
      io << " flags={" << flags_str.strip << "}" unless flags_str.empty?
    end
  end
end
