#!/usr/bin/env crystal
require "../src/libpcap"

# List devices
puts "Available devices:"
LibPcap::Device.all.each do |dev|
  puts "  #{dev}"
end

# Pick the first device
device = LibPcap::Device.all.first
puts "\nCapturing on #{device.name} ..."

handle = LibPcap::PcapHandle.for_live(device)
handle.snaplen = 65536
handle.promisc = false
handle.timeout_ms = 1000
handle.activate

# Set a filter (optional)
# handle.filter = "tcp and port 80"

count = 0
handle.loop(count: 10) do |packet|
  puts "Packet #{count += 1}: #{packet.len} bytes at #{packet.timestamp}"
  begin
    eth = packet.ethernet
    puts "  MAC: #{eth.src_mac} -> #{eth.dst_mac} (type 0x#{eth.ethertype.to_s(16)})"
    if ip = packet.ipv4?
      puts "  IP: #{ip.src_ip} -> #{ip.dst_ip} (proto #{ip.protocol})"
    end
  rescue ex
    puts "  Parsing error: #{ex.message}"
  end
end

handle.close
puts "Done."
