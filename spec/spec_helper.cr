require "spec"
require "../src/libpcap"

# Helper: create a temporary pcap file with a single packet.
# Returns the file path.
def create_test_pcap : String
  temp = File.tempfile("test_", ".pcap")
  path = temp.path
  temp.close

  # Build synthetic Ethernet + IPv4 + TCP packet using Bytes literals
  eth = Bytes[0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
    0x08, 0x00] # ethertype IPv4

  ip = Bytes[0x45, 0x00, 0x00, 0x28, # version=4, IHL=5, tos, total len=40
    0x00, 0x00, 0x00, 0x00,          # id, flags/frag
    0x40, 0x06, 0x00, 0x00,          # TTL=64, proto=TCP, checksum=0
    0xC0, 0xA8, 0x01, 0x01,          # src 192.168.1.1
    0xC0, 0xA8, 0x01, 0x02]          # dst 192.168.1.2

  tcp = Bytes[0x00, 0x50,   # src port 80
    0x00, 0x00,             # dst port 0
    0x00, 0x00, 0x00, 0x00, # seq
    0x00, 0x00, 0x00, 0x00, # ack
    0x50, 0x02,             # data offset=5, flags=SYN
    0x00, 0x00,             # window
    0x00, 0x00,             # checksum
    0x00, 0x00]             # urgent

  payload = Bytes.new(10, 0xAA)

  now = Time.utc
  ts_sec = now.to_unix
  ts_usec = now.nanosecond // 1000

  # Build pcap file in memory using IO::Memory
  io = IO::Memory.new

  # Global header (24 bytes)
  io.write_bytes(0xa1b2c3d4_u32, IO::ByteFormat::LittleEndian) # magic
  io.write_bytes(2_u16, IO::ByteFormat::LittleEndian)          # version major
  io.write_bytes(4_u16, IO::ByteFormat::LittleEndian)          # version minor
  io.write_bytes(0_u32, IO::ByteFormat::LittleEndian)          # timezone offset
  io.write_bytes(0_u32, IO::ByteFormat::LittleEndian)          # timestamp precision
  io.write_bytes(65535_u32, IO::ByteFormat::LittleEndian)      # snaplen
  io.write_bytes(1_u32, IO::ByteFormat::LittleEndian)          # network (DLT_EN10MB)

  # Packet record header (16 bytes)
  io.write_bytes(ts_sec.to_u32, IO::ByteFormat::LittleEndian)  # timestamp seconds
  io.write_bytes(ts_usec.to_u32, IO::ByteFormat::LittleEndian) # timestamp microseconds
  caplen = (eth.size + ip.size + tcp.size + payload.size).to_u32
  io.write_bytes(caplen, IO::ByteFormat::LittleEndian) # caplen
  io.write_bytes(caplen, IO::ByteFormat::LittleEndian) # len

  # Write packet data in parts
  io.write(eth)
  io.write(ip)
  io.write(tcp)
  io.write(payload)

  # Write to file
  File.write(path, io.to_slice)

  path
end

# Helper to generate a synthetic packet for parsing tests.
# (Currently unused, but kept for completeness)
def synthetic_packet_data
  eth = Bytes[0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
    0x08, 0x00]
  ip = Bytes[0x45, 0x00, 0x00, 0x28,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01,
    0xC0, 0xA8, 0x01, 0x02]
  tcp = Bytes[0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00]
  payload = Bytes.new(10, 0xAA)
  eth + ip + tcp + payload
end
