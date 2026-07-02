# Device enumeration and representation.
#
# Uses `pcap_findalldevs` and manual pointer offsets to extract device info.
require "socket"
require "../lib/lib_pcap"

module LibPcap
  class Device
    getter name : String
    getter description : String?
    getter flags : UInt32
    getter addresses : Array(Address)

    # Represents a network address associated with an interface.
    struct Address
      getter addr : Socket::Address?
      getter netmask : Socket::Address?
      getter broadaddr : Socket::Address?
      getter dstaddr : Socket::Address?

      def initialize(addr : LibC::Sockaddr*, netmask : LibC::Sockaddr*, broadaddr : LibC::Sockaddr*, dstaddr : LibC::Sockaddr*)
        @addr = sockaddr_to_address(addr)
        @netmask = sockaddr_to_address(netmask)
        @broadaddr = sockaddr_to_address(broadaddr)
        @dstaddr = sockaddr_to_address(dstaddr)
      end

      private def sockaddr_to_address(sa : LibC::Sockaddr*) : Socket::Address?
        return nil if sa.null?
        # Some address families (e.g., AF_PACKET on Linux) are not supported
        # by Crystal's Socket::Address; we catch and return nil.
        begin
          Socket::Address.from(sa)
        rescue
          nil
        end
      end

      # Returns the IP address as a string (if it's an IPv4 or IPv6 address).
      def ip_address : String?
        if a = @addr
          if a.family == Socket::Family::INET || a.family == Socket::Family::INET6
            return a.to_s
          end
        end
        nil
      end
    end

    protected def initialize(@name : String, @description : String?, @flags : UInt32, @addresses : Array(Address))
    end

    # Returns an array of all available capture devices.
    #
    # Raises `OpenError` if `pcap_findalldevs` fails.
    def self.all : Array(Device)
      errbuf = Bytes.new(PCAP_ERRBUF_SIZE)
      dev_list = Pointer(LibPcap::PcapIf).null
      rc = LibPcap::C.findalldevs(pointerof(dev_list), errbuf)
      if rc != 0
        raise OpenError.new("pcap_findalldevs failed", String.new(errbuf))
      end

      devices = [] of Device
      current = dev_list

      while !current.null?
        iface = current.value

        name = iface.name.null? ? "unknown" : String.new(iface.name)
        description = iface.description.null? ? nil : String.new(iface.description)
        flags = iface.flags

        addresses = [] of Address
        addr_ptr = iface.addresses

        while !addr_ptr.null?
          addr_val = addr_ptr.value
          addresses << Address.new(
            addr_val.addr,
            addr_val.netmask,
            addr_val.broadaddr,
            addr_val.dstaddr
          )
          addr_ptr = addr_val.next_addr
        end

        devices << Device.new(name, description, flags, addresses)
        current = iface.next_if
      end

      LibPcap::C.freealldevs(dev_list)
      devices
    end

    # Look up the network address and netmask for a given device name.
    #
    # Returns a tuple `{network, netmask}` as `UInt32` in network byte order.
    # Raises `OpenError` on failure.
    def self.lookup(device_name : String) : {UInt32, UInt32}
      errbuf = Bytes.new(PCAP_ERRBUF_SIZE)
      net = 0_u32
      mask = 0_u32
      rc = LibPcap::C.lookupnet(device_name.to_unsafe, pointerof(net), pointerof(mask), errbuf)
      if rc != 0
        raise OpenError.new("pcap_lookupnet failed for '#{device_name}'", String.new(errbuf))
      end
      {net, mask}
    end

    # Returns a human‑readable description.
    def to_s(io : IO) : Nil
      io << name
      if desc = @description
        io << " (" << desc << ")"
      end
    end
  end
end
