# User Guide

Welcome to the **pcap** Crystal library – your gateway to packet capture, filtering, and pcap file manipulation.

---

## 1. Introduction

`pcap` provides idiomatic Crystal bindings to libpcap, the de‑facto standard for network packet capture on Unix‑like systems. With this library you can:

- Enumerate network interfaces.
- Capture live packets with BPF filters.
- Read and write pcap files.
- Parse Ethernet, IPv4, TCP, and UDP headers.
- Inject packets onto the network.
- Control timestamp precision, direction, and non‑blocking behaviour.

This guide walks you through the essential workflows.

---

## 2. Installation

### System Dependencies

You need libpcap development headers. Install them according to your system:

- **Debian/Ubuntu**: `sudo apt install libpcap-dev`
- **Fedora/RHEL**: `sudo dnf install libpcap-devel`
- **Arch Linux**: `sudo pacman -S libpcap`
- **macOS (Homebrew)**: `brew install libpcap`
- **FreeBSD/OpenBSD**: libpcap is installed by default.

### Shard Setup

Add the following to your `shard.yml`:

```yaml
dependencies:
  pcap:
    github: OkaVatti/pcap
    version: ~> 0.1.0
```

Then run shards install and require it in your code:

```crystal
require "pcap"
```

---

3. Device Handling

**List all available devices**:

```crystal
devices = LibPcap::Device.all
devices.each do |dev|
    puts "#{dev.name} (#{dev.description || "no description"})"
    dev.addresses.each do |addr|
        if ip = addr.ip_address
            puts " IP: #{ip}"
        end
    end
end
```

Obtain the network address and netmask for a specific device:

```crystal
net, mask = LibPcap::Device.lookup("eth0")
puts "Network: #{IPAddress.new(net)}" # you need to format
```

4. Creating a Capture Handle
   **Live Capture**

```crystal
device = LibPcap::Device.all.first
handle = LibPcap::PcapHandle.for_live(device)
```

**Offline File Reading**

```crystal
handle = LibPcap::PcapHandle.for_offline("capture.pcap")
# or with nano‑second precision:
handle = LibPcap::PcapHandle.for_offline_with_precision("capture.pcap", LibPcap::PCAP_TSTAMP_PRECISION_NANO)
```

**Dead Handle** (for writing)

```crystal
handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB) # Ethernet
```

5. Configuration and Activation

**Set parameters** (must be done before activation):

```crystal
handle.snaplen = 65536
handle.promisc = false
handle.timeout_ms = 1000
handle.buffer_size = 1024 \* 1024
handle.immediate_mode = true
handle.rfmon = false # monitor mode (for Wi‑Fi)
```

**Activate**:

```crystal
handle.activate
```

If activation fails, an `ActivationError` is raised.

6. Capturing Packets
   **Using `#loop` (callback‑based)**

```crystal
handle.loop(count: 10) do |packet|
    puts "Packet: #{packet.len} bytes"
end
```

`count: 0` (the default) captures indefinitely until you call `handle.breakloop()` from another thread or signal handler.

**Using `#next_packet`** (single packet, non‑callback)

```crystal
loop do
  result = handle.next_packet
  case result
  when .ok?
    packet = result.value
    # process packet
  when .eof?
    break   # end of file
  when .error?
    raise result.error
  end
end
```

**Using `#dispatch`** (non‑blocking)

`dispatch` processes up to a given number of packets and returns immediately. It is useful when you combine it with `selectable_fd` in an event loop.

```crystal
handle.nonblock = true
fd = handle.selectable_fd

# In your event loop:
handle.dispatch(10) do |packet|
  # process packet
end
```

7. BPF Filters

**Set a filter before or after activation** (but before capturing):

```crystal
handle.filter = "tcp and port 80"
handle.loop { |packet| ... }
```

See the pcap‑filter(7) man page for filter syntax.

8. Parsing Packets

**The `Packet` class provides lazy parsing**:

```crystal
handle.loop do |packet|
  eth = packet.ethernet
  puts "MAC: #{eth.src_mac} -> #{eth.dst_mac}"

  # Only if IPv4
  if ip = packet.ipv4?
    puts "IP: #{ip.src_ip} -> #{ip.dst_ip} (proto #{ip.protocol})"
    if ip.protocol == 6
      tcp = packet.tcp
      puts "TCP: #{tcp.src_port} -> #{tcp.dst_port} flags=#{tcp.flags}"
    elsif ip.protocol == 17
      udp = packet.udp
      puts "UDP: #{udp.src_port} -> #{udp.dst_port} len=#{udp.length}"
    end
  end
end
```

The `?`‑versions (`ipv4?`, `tcp?`, `udp?`) return `nil` if the packet does not contain that header, avoiding exceptions.

9. Writing Savefiles

**Using `SavefileWriter`** (high‑level)

```crystal
hanhandle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
writer = LibPcap::SavefileWriter.new(handle, "output.pcap")

# Write a synthetic packet
data = Bytes[0x00, 0x11, ...] # Ethernet frame
header = LibPcap::PcapPkthdr.new(ts: ..., caplen: data.size.to_u32, len: data.size.to_u32)
writer.write(header, data)
writer.close
```

**Direct Dumper Usage** (low‑level)

```crystal
dumper = handle.open_dumper("output.pcap")
dumper.dump(packet) # or dump(header, data)
dumper.flush
dumper.close
```

10. Reading Savefiles

```crystal
reader = LibPcap.open_offline("capture.pcap")
reader.each_packet do |packet|
  puts packet.len
end
reader.close
```

11. Advanced Features
    **Non‑blocking Mode**

```crystal
handle.nonblock = true
handle.nonblock? # => true
fd = handle.selectable_fd
```

Use the file descriptor with your own event loop (e.g., `select`, `epoll`, `kqueue`). Then call `dispatch` to process packets when data is available.

**Timestamp Precision and Type**

```crystal
# Set precision before activation
handle.tstamp_precision = LibPcap::PCAP_TSTAMP_PRECISION_NANO

# List and set timestamp type (before activation)
types = handle.tstamp_types
if types.includes?(LibPcap::PCAP_TSTAMP_ADAPTER)
  handle.tstamp_type = LibPcap::PCAP_TSTAMP_ADAPTER
end
```

**Direction Control**

```crystal
handle.activate
handle.direction = LibPcap::PCAP_D_INOUT # capture both in and out
```

**Packet Injection**

```crystal
# Requires appropriate privileges (e.g., root)
data = Bytes[0x00, 0x11, ...] # a valid Ethernet frame
bytes_sent = handle.inject(data)
```

**Remote Capture**

Compile with `-D remote` and then:

```crystal
handle = LibPcap::PcapHandle.for_remote(
  source: "rpcap://192.168.1.100/eth0",
  snaplen: 65536,
  flags: LibPcap::PCAP_OPENFLAG_PROMISCUOUS,
  auth_type: LibPcap::PCAP_RMTAUTH_PWD,
  username: "user",
  password: "pass"
)
handle.loop { |packet| ... }
```

**Protocol Setting** (Linux‑specific)

Compile with `-D protocol`:

```crystal
handle.protocol = LibPcap::PCAP_PROTOCOL_ETHERNET # use Ethernet header
```

12. Error Handling

Most operations raise exceptions. The hierarchy is:

- `LibPcap::Error` (base)
  - `OpenError`
  - `ConfigurationError`
  - `ActivationError`
  - `FilterError`
  - `BreakLoopError`
  - `DumperError`
  - `TimeoutError`

For operations like `next_packet`, which can fail due to EOF, the `Result(T)` type is used:

```crystal
result = handle.next_packet
if result.ok?
  packet = result.value
elsif result.eof?
  # end of file
else
  # error
end
```

13. Performance Considerations

- Use `snaplen` to limit captured packet size (reduces memory/cpu).
- Enable `immediate_mode` for low‑latency applications.
- Use `dispatch` with `selectable_fd` to integrate with event loops.
- Reuse packet buffers if you are processing large volumes.

14. Troubleshooting

**"pcap_activate failed with code -8"**
The device may be down (PCAP_ERROR_IFACE_NOT_UP). Bring it up (e.g., ip link set eth0 up).

**"No usable network interface found for live capture"**
Ensure you have at least one interface up. On Linux, the "any" pseudo‑device works when permissions allow.

**Permission denied**
Capturing and injecting require root or CAP_NET_RAW. Use sudo or set capabilities.

**Remote capture not working**
Ensure `libpcap` was compiled with `--enable-remote`. Build your application with `-D remote`.

**Append mode fails**
Your `libpcap` version may be older than 1.9.0. Upgrade or use normal write mode.

15. Further Help

- Check the API reference for detailed method signatures.
- Read the internals for developer insights.
- Report issues or ask questions on the GitHub repository.

**_Happy capturing!_**
