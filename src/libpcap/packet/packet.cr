# A captured packet with metadata and raw payload.
#
# Provides lazy access to link‑layer headers and higher‑level protocols.
# Headers are parsed on‑demand and cached.
require "../lib/lib_pcap"

module LibPcap
  class Packet
    getter header_ptr : LibPcap::PcapPkthdr*
    getter data : Bytes
    @ethernet : EthernetHeader?
    @ipv4 : IPv4Header?
    @tcp : TCPHeader?
    @udp : UDPHeader?

    def initialize(@header_ptr : LibPcap::PcapPkthdr*, @data : Bytes)
    end

    # Timestamp as a Crystal `Time` (converted from `struct timeval`).
    def timestamp : Time
      tv = @header_ptr.value.ts
      Time.unix(tv.tv_sec) + Time::Span.new(nanoseconds: tv.tv_usec * 1000)
    end

    def caplen : UInt32
      @header_ptr.value.caplen
    end

    def len : UInt32
      @header_ptr.value.len
    end

    # ------------------------------------------------------------
    # Link‑Layer Parsing (Ethernet by default)
    # ------------------------------------------------------------

    # Returns the Ethernet header if the link‑layer is Ethernet (DLT_EN10MB).
    #
    # Raises `Error` if the datalink is not Ethernet.
    def ethernet : EthernetHeader
      @ethernet ||= EthernetHeader.new(@data)
    rescue ex
      raise Error.new("Not an Ethernet frame or data too short", ex.message)
    end

    # ------------------------------------------------------------
    # Higher‑Layer Protocol Access
    # ------------------------------------------------------------

    # Returns the IPv4 header if the Ethernet payload is IPv4 (0x0800).
    def ipv4 : IPv4Header
      @ipv4 ||= begin
        eth = ethernet
        unless eth.ethertype == 0x0800
          raise Error.new("Ethertype is not IPv4 (0x0800), got 0x#{eth.ethertype.to_s(16)}")
        end
        IPv4Header.new(eth.payload)
      end
    end

    # Returns the TCP header if the IPv4 protocol is TCP (6).
    def tcp : TCPHeader
      @tcp ||= begin
        ip = ipv4
        unless ip.protocol == 6
          raise Error.new("IP protocol is not TCP (6), got #{ip.protocol}")
        end
        TCPHeader.new(ip.payload)
      end
    end

    # Returns the UDP header if the IPv4 protocol is UDP (17).
    def udp : UDPHeader
      @udp ||= begin
        ip = ipv4
        unless ip.protocol == 17
          raise Error.new("IP protocol is not UDP (17), got #{ip.protocol}")
        end
        UDPHeader.new(ip.payload)
      end
    end

    # The raw payload after all parsed headers (e.g., TCP/UDP payload).
    # Returns `nil` if no higher‑level protocol could be parsed.
    def payload : Bytes?
      if tcp = @tcp
        tcp.payload
      elsif udp = @udp
        udp.payload
      else
        nil
      end
    end
  end
end
