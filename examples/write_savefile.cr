#!/usr/bin/env crystal
require "../src/libpcap"

# Create a dead handle for Ethernet
handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)

# Create a writer
writer = LibPcap::SavefileWriter.new(handle, "generated.pcap")

# Build a fake packet
eth = StaticArray[0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
  0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
  0x08, 0x00].to_slice
ip = StaticArray[0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00,
  0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01,
  0xC0, 0xA8, 0x01, 0x02].to_slice
payload = Bytes.new(10, 0xAA)
packet_data = eth + ip + payload

# Timestamp
now = Time.utc
tv = LibC::Timeval.new
tv.tv_sec = now.to_unix
tv.tv_usec = now.nanosecond // 1000

header = LibPcap::PcapPkthdr.new(
  ts: tv,
  caplen: packet_data.size.to_u32,
  len: packet_data.size.to_u32
)

# Write the packet
writer.write(header, packet_data)
puts "Wrote one packet to generated.pcap"

writer.close
