# pcap – Crystal bindings for libpcap

**Production‑ready, idiomatic Crystal bindings for the libpcap library** – capture, filter, inject, and read/write pcap files with ease.

---

## Features

- ✅ **Device enumeration** – list interfaces, addresses, and flags.
- ✅ **Live packet capture** – with configurable snap length, promiscuous mode, timeouts, and buffer size.
- ✅ **Offline savefile reading** – iterate over packets from pcap/pcapng files.
- ✅ **BPF filtering** – compile and apply any Berkeley Packet Filter expression.
- ✅ **Packet parsing** – built‑in support for Ethernet, IPv4, TCP, and UDP headers.
- ✅ **Savefile writing** – write packets to pcap files (including append mode).
- ✅ **Non‑blocking capture** – integrate with event loops via `selectable_fd`.
- ✅ **Timestamp control** – choose precision (micro/nano) and timestamp type (host, adapter, etc.).
- ✅ **Packet injection** – send raw packets on the network (requires appropriate privileges).
- ✅ **Direction filtering** – capture only incoming/outgoing/both packets.
- ✅ **Remote capture** (optional) – capture from rpcap servers (build with `-D remote`).
- ✅ **Linux‑specific protocol headers** (optional) – use `-D protocol` to enable.
- ✅ **Comprehensive error handling** – typed exceptions and a `Result(T)` monad.
- ✅ **RAII resource management** – automatic cleanup via finalizers.
- ✅ **Thorough test suite** – 40+ examples, all passing.

---

## Installation

Add the shard to your `shard.yml`:

```yaml
dependencies:
  pcap:
    github: OkaVatti/pcap
    version: ~> 0.1.0
```

Then run:

```bash
shards install
```

You also need the libpcap development headers installed on your system:

- **Debian/Ubuntu**: `sudo apt install libpcap-dev`
- **Fedora/RHEL**: `sudo dnf install libpcap-devel`
- **Arch Linux**: `sudo pacman -S libpcap`
- **macOS** (Homebrew): `brew install libpcap`
- **FreeBSD/OpenBSD**: installed by default

---

## Quick Start

### List available devices

```crystal
require "pcap"

devices = LibPcap::Device.all
devices.each do |dev|
  puts "#{dev.name} (#{dev.description})"
  dev.addresses.each do |addr|
    if ip = addr.ip_address
      puts "  IP: #{ip}"
    end
  end
end
```

### Capture 10 packets on the first device

```crystal
device = LibPcap::Device.all.first
handle = LibPcap::PcapHandle.for_live(device)
handle.snaplen = 65536
handle.promisc = false
handle.timeout_ms = 1000
handle.activate

handle.loop(count: 10) do |packet|
  puts "Packet: #{packet.len} bytes at #{packet.timestamp}"
  eth = packet.ethernet
  puts "  MAC: #{eth.src_mac} -> #{eth.dst_mac}"
  if ip = packet.ipv4? # optional (returns nil if not IPv4)
    puts "  IP: #{ip.src_ip} -> #{ip.dst_ip}"
  end
end
handle.close
```

### Read a pcap file

```crystal
reader = LibPcap.open_offline("capture.pcap")
reader.each_packet do |packet|
  puts "Packet: #{packet.len} bytes"
  # parse as needed...
end
reader.close
```

### Write a synthetic packet to a new file

```crystal
handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
writer = LibPcap::SavefileWriter.new(handle, "output.pcap")

# Build a dummy Ethernet frame
data = Bytes[0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  # dst MAC
             0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  # src MAC
             0x08, 0x00]                           # Ethertype IPv4

now = Time.utc
tv = LibC::Timeval.new
tv.tv_sec = now.to_unix
tv.tv_usec = now.nanosecond // 1000

header = LibPcap::PcapPkthdr.new(
  ts: tv,
  caplen: data.size.to_u32,
  len: data.size.to_u32
)
writer.write(header, data)
writer.close
```

---

## Advanced Usage

### BPF Filtering

```crystal
handle.filter = "tcp and port 80"
handle.loop do |packet|
  # only TCP port 80 packets
end
```

### Non‑blocking Capture (with select/poll)

```crystal
handle.nonblock = true
fd = handle.selectable_fd  # get the file descriptor
# Use fd with `select`, `epoll`, `kqueue`, etc.
loop do
  # wait for readability on fd...
  handle.dispatch(10) do |packet|
    # process packet
  end
end
```

### Inject a Packet

```crystal
data = Bytes[0x00, 0x11, ...] # valid Ethernet frame
handle.inject(data)            # returns number of bytes sent
# or handle.sendpacket(data)
```

### Choose Timestamp Type

```crystal
# List available types
types = handle.tstamp_types
if types.includes?(LibPcap::PCAP_TSTAMP_HOST_HIPREC)
  handle.tstamp_type = LibPcap::PCAP_TSTAMP_HOST_HIPREC
end
```

### Remote Capture (rpcap)

Build with `-D remote` and then:

```crystal
handle = LibPcap::PcapHandle.for_remote(
  source: "rpcap://192.168.1.100/eth0",
  flags: LibPcap::PCAP_OPENFLAG_PROMISCUOUS
)
handle.loop { |packet| ... }
handle.close
```

---

## Compilation Flags

The library supports optional features that may not be available in all libpcap installations.

| Flag          | Description                                                   |
| ------------- | ------------------------------------------------------------- |
| `-D remote`   | Enable remote capture functions (`pcap_open`).                |
| `-D protocol` | Enable Linux‑specific protocol setting (`pcap_set_protocol`). |

Example:

```bash
shards build --release -D remote -D protocol
```

---

## Testing

Run the full test suite:

```bash
crystal spec
```

Some tests require a live network interface. To run them, set:

```bash
TEST_LIVE=1 crystal spec
```

If no live device is available, those tests will be skipped gracefully.

Remote capture tests require a remote server and can be enabled with:

```bash
TEST_REMOTE=1 TEST_REMOTE_SOURCE=rpcap://host/interface crystal spec -D remote
```

---

## Documentation

- **API Reference** – generate with `crystal docs`. The source code is thoroughly commented.
- **User Guide** – see `docs/guide.md` (in progress).
- **Internals** – see `docs/internals.md` for FFI details.

We welcome contributions to improve documentation.

---

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Add your changes with tests.
4. Ensure `crystal spec` passes.
5. Submit a pull request.

Please follow the [Crystal Code of Conduct](https://crystal-lang.org/conduct/).

---

## License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## Acknowledgements

- The libpcap team for the original C library.
- The Crystal community for an elegant language and ecosystem.

---

**Happy packet capturing!** 🐧📡
