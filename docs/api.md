# API Reference

> **Full API documentation** can be generated with `crystal docs`. This page provides a quick overview of the public API.

---

## Module `LibPcap`

The top‑level namespace for all functionality.

### Constants

- `VERSION` – current library version (e.g., `"0.1.0"`).

### Class Methods

- **`version : String`** – returns the libpcap library version string.

- **`init(optimization : Int32 = 0) : Nil`** – (optional) initializes libpcap globally. Usually not required.

- **`open_offline(path : String) : SavefileReader`** – opens a pcap/pcapng file for reading.

- **`create_writer(handle : PcapHandle, filename : String) : SavefileWriter`** – creates a writer for the given handle and output file.

---

## Class `Device`

Represents a network capture device.

### Getters

- `name : String` – device name (e.g., `"eth0"`).
- `description : String?` – human‑readable description (if available).
- `flags : UInt32` – interface flags (IFF\_\*).
- `addresses : Array(Address)` – associated network addresses.

### Nested Struct `Address`

- `addr : Socket::Address?` – the address.
- `netmask : Socket::Address?` – netmask.
- `broadaddr : Socket::Address?` – broadcast address.
- `dstaddr : Socket::Address?` – destination address (point‑to‑point).
- `ip_address : String?` – returns a string representation if the address is IPv4 or IPv6.

### Class Methods

- **`all : Array(Device)`** – enumerates all available capture devices. Raises `OpenError` on failure.

- **`lookup(device_name : String) : {UInt32, UInt32}`** – returns the network address and netmask (in network byte order) for the given device. Raises `OpenError` on failure.

### Instance Methods

- **`to_s(io : IO) : Nil`** – prints the device name and description.

---

## Class `PcapHandle`

The main handle for live capture, offline reading, or writing.

### Constructors

- **`for_live(device : Device | String) : self`** – creates a handle for live capture (not yet activated).

- **`for_offline(path : String) : self`** – opens a savefile for reading (already activated).

- **`for_offline_with_precision(path : String, precision : Int32) : self`** – opens a savefile with the given timestamp precision (`PCAP_TSTAMP_PRECISION_*`).

- **`dead(datalink : Int32, snaplen : Int32 = 65535) : self`** – creates a "dead" handle for writing savefiles.

- **`for_remote(..., auth_type, username, password) : self`** – opens a remote capture session (requires `-D remote`).

### Configuration (must be called before `#activate`)

- **`snaplen=(value : Int)`**
- **`promisc=(on : Bool)`**
- **`timeout_ms=(ms : Int)`**
- **`buffer_size=(bytes : Int)`**
- **`immediate_mode=(on : Bool)`**
- **`rfmon=(on : Bool)`**
- **`tstamp_precision=(precision : Int32)`** – micro/nano.
- **`tstamp_type=(type : Int32)`** – one of `PCAP_TSTAMP_*`.
- **`protocol=(proto : Int32)`** – Linux‑specific; requires `-D protocol`.

### Activation

- **`activate : Nil`** – activates the handle. Raises `ActivationError` on failure.

- **`active? : Bool`** – returns `true` if the handle is active.

### Packet Capture

- **`loop(count : Int = 0, &block : Packet -> _) : Nil`** – captures packets in a loop. `count=0` means infinite until `#breakloop`. Raises `BreakLoopError` if broken, or `Error` on other failures.

- **`next_packet : Result(Packet)`** – fetches the next packet. Returns `Result(Packet).ok`, `.eof`, or `.error`.

- **`dispatch(count : Int = -1, &block : Packet -> _) : Nil`** – processes up to `count` available packets and returns immediately. Similar to `loop` but non‑blocking.

- **`breakloop : Nil`** – interrupts a running `loop` from another thread or signal handler.

### Filtering

- **`filter=(expression : String)`** – compiles and sets a BPF filter. Raises `FilterError` on failure.

### Statistics

- **`stats : {UInt32, UInt32, UInt32}`** – returns `{received, dropped, if_dropped}`. Raises `Error` on failure.

### Datalink Helpers

- **`datalink : Int32`** – current DLT\_\* value.
- **`datalink=(dlt : Int32)`** – sets the datalink type (if supported).
- **`datalink_name : String`** – human‑readable name.
- **`datalink_types : Array(Int32)`** – list of supported DLT\_\* values.

### Timestamp Types

- **`tstamp_types : Array(Int32)`** – list of supported timestamp types.
- **`tstamp_type=(type : Int32)`** – sets the timestamp type (must be called before activation).

### Non‑blocking Mode

- **`nonblock=(on : Bool)`** – enables/disables non‑blocking mode.
- **`nonblock? : Bool`** – returns `true` if non‑blocking is active.
- **`selectable_fd : Int32?`** – returns the file descriptor for select/poll, or `nil` if not available.

### Direction Control

- **`direction=(dir : Int32)`** – sets capture direction (`PCAP_D_IN`, `PCAP_D_OUT`, `PCAP_D_INOUT`).

### Packet Injection

- **`inject(data : Bytes) : Int32`** – injects a raw packet. Returns bytes sent. Raises `Error` on failure.
- **`sendpacket(data : Bytes) : Int32`** – alias for `#inject`.

### Dumper Management

- **`open_dumper(filename : String) : PcapDumper`** – opens a dumper for writing.
- **`open_dumper_append(filename : String) : PcapDumper`** – opens a dumper in append mode (requires libpcap ≥1.9.0).

### Utility

- **`statustostr(error : Int32) : String`** – class method that converts a libpcap error code to a string.

### Resource Management

- **`close : Nil`** – explicitly closes the handle.

---

## Class `Packet`

Represents a captured packet.

### Getters

- `header_ptr : PcapPkthdr*` – pointer to the C header.
- `data : Bytes` – raw packet data.
- `timestamp : Time` – capture timestamp.
- `caplen : UInt32` – captured length.
- `len : UInt32` – original length.

### Parsing Methods

- **`ethernet : EthernetHeader`** – parses Ethernet header (raises if not Ethernet).
- **`ipv4 : IPv4Header`** – parses IPv4 header (raises if not IPv4).
- **`tcp : TCPHeader`** – parses TCP header (raises if not TCP).
- **`udp : UDPHeader`** – parses UDP header (raises if not UDP).
- **`payload : Bytes?`** – returns the application‑layer payload if TCP or UDP is parsed.

---

## Class `EthernetHeader`

- `data : Bytes` – full header (14 bytes).
- `dst_mac : String` – destination MAC.
- `src_mac : String` – source MAC.
- `ethertype : UInt16` – Ethertype value.
- `payload : Bytes` – rest of the frame.

---

## Class `IPv4Header`

- `raw : Bytes` – header bytes.
- `version : UInt8` – should be 4.
- `header_len : Int32` – header length in bytes.
- `tos : UInt8` – Type of Service.
- `total_len : UInt16` – total packet length.
- `id : UInt16` – identification.
- `flags_fragment : UInt16` – combined flags and fragment offset.
- `df? : Bool` – Don't Fragment flag.
- `mf? : Bool` – More Fragments flag.
- `fragment_offset : UInt16` – fragment offset.
- `ttl : UInt8` – Time to Live.
- `protocol : UInt8` – protocol number.
- `checksum : UInt16` – header checksum.
- `src_ip_raw : UInt32` – source IP (network order).
- `dst_ip_raw : UInt32` – destination IP (network order).
- `src_ip : String` – source IP as dotted decimal.
- `dst_ip : String` – destination IP as dotted decimal.
- `options : Bytes` – options bytes.
- `each_option(&)` – iterates over options.
- `payload : Bytes` – the payload after the IPv4 header.

---

## Class `TCPHeader`

- `raw : Bytes` – header bytes.
- `src_port : UInt16`
- `dst_port : UInt16`
- `seq_num : UInt32`
- `ack_num : UInt32`
- `data_offset : UInt8` – header length in 32‑bit words.
- `header_len : Int32` – header length in bytes.
- `reserved : UInt8` – reserved bits.
- `flags : UInt16` – flags (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN).
- `ns?`, `cwr?`, `ece?`, `urg?`, `ack?`, `psh?`, `rst?`, `syn?`, `fin?` – flag predicates.
- `window : UInt16`
- `checksum : UInt16`
- `urgent : UInt16`
- `options : Bytes` – options bytes.
- `each_option(&)` – iterates over options.
- `payload : Bytes` – TCP payload.

---

## Class `UDPHeader`

- `raw : Bytes` – header bytes.
- `src_port : UInt16`
- `dst_port : UInt16`
- `length : UInt16` – UDP length (header + payload).
- `checksum : UInt16`
- `payload : Bytes` – UDP payload.

---

## Classes `SavefileReader` / `SavefileWriter`

- **`SavefileReader#each_packet(&block : Packet -> _)`** – iterates over all packets.
- **`SavefileWriter#write(packet : Packet)`** or **`#write(header : PcapPkthdr, data : Bytes)`** – writes a packet.
- **`SavefileWriter#capture_loop(count : Int = 0, &block : Packet -> Bool)`** – captures and writes packets until `block` returns `false`.

---

## Class `PcapDumper`

Low‑level dumper handle.

- **`dump(header : PcapPkthdr*, data : Bytes)`**
- **`dump(packet : Packet)`**
- **`flush : Nil`**
- **`ftell : Int64`**
- **`close : Nil`**

---

## Errors

All exceptions inherit from `LibPcap::Error`.

- `OpenError`
- `ConfigurationError`
- `ActivationError`
- `FilterError`
- `BreakLoopError`
- `DumperError`
- `TimeoutError`

---

## Result(T)

- `Result(T).ok(value)`, `.eof`, `.error(error)` – constructors.
- `#ok?`, `#eof?`, `#error?` – predicates.
- `#unwrap!` – returns the value on `Ok`, raises on `Eof` or `Error`.
