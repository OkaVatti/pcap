require "../../spec_helper"

describe LibPcap::Device do
  describe ".all" do
    it "returns an array of devices" do
      devices = LibPcap::Device.all
      devices.should be_a(Array(LibPcap::Device))
    end

    it "returns devices with non-empty names" do
      devices = LibPcap::Device.all
      devices.each do |dev|
        dev.name.should_not be_empty
      end
    end

    it "returns devices with flags" do
      devices = LibPcap::Device.all
      devices.each do |dev|
        dev.flags.should be_a(UInt32)
      end
    end

    it "returns devices with description (may be nil)" do
      devices = LibPcap::Device.all
      devices.each do |dev|
        if desc = dev.description
          desc.should be_a(String)
        end
      end
    end

    it "returns devices with addresses array and proper parsing" do
      devices = LibPcap::Device.all
      devices.each do |dev|
        dev.addresses.should be_a(Array(LibPcap::Device::Address))
        dev.addresses.each do |addr|
          # Check that each address field is either nil or a Socket::Address
          if a = addr.addr
            a.should be_a(Socket::Address)
            # If it's an IP family, ip_address should return a string
            if a.family == Socket::Family::INET || a.family == Socket::Family::INET6
              addr.ip_address.should_not be_nil
              addr.ip_address.should be_a(String)
            end
          end
          if netmask = addr.netmask
            netmask.should be_a(Socket::Address)
          end
          if broadaddr = addr.broadaddr
            broadaddr.should be_a(Socket::Address)
          end
          if dstaddr = addr.dstaddr
            dstaddr.should be_a(Socket::Address)
          end
        end
      end
    end
  end

  describe ".lookup" do
    it "looks up a device by name" do
      devices = LibPcap::Device.all
      if devices.empty?
        pending "No devices found, skipping lookup test"
      else
        dev = devices.first
        net, mask = LibPcap::Device.lookup(dev.name)
        net.should be_a(UInt32)
        mask.should be_a(UInt32)
      end
    end
  end
end
