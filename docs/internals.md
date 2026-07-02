# Internals – How the Bindings Work

This document is intended for developers who wish to understand the design and implementation of the Crystal libpcap bindings, or who plan to extend them.

---

## 1. FFI Architecture

The bindings are built on Crystal's built‑in **foreign function interface (FFI)**. The low‑level declarations are in `src/libpcap/lib/lib_pcap.cr`.

### The `lib` block

All C functions are declared inside a `lib C` block with `@[Link("pcap")]`, which instructs the compiler to link against `libpcap`.

```crystal
@[Link("pcap")]
lib C
  fun pcap_findalldevs(...)
  # etc.
end
```

We follow a naming convention: `pcap_foo` becomes `foo` in Crystal (without the prefix) to improve readability in high‑level wrappers.

**Type Mapping**

- C pointers (`u_char*`, `const char*`) are mapped to `UInt8*` or `UInt8*` in Crystal.
- Opaque handles (`pcap_t*`, `pcap_dumper_t*`) are represented by `PcapT*` and `PcapDumperT*` structs (defined in `structs.cr`). These are empty (dummy) structs but have a dummy field to satisfy Crystal's requirement for non‑empty structs (≥ 1.20.2).

## 2. Extern Structs

C structures are mirrored with `@[Extern]` structs. They must have the same memory layout as the C counterparts. For example:

```crystal
@[Extern]
struct PcapPkthdr
property ts : LibC::Timeval
property caplen : UInt32
property len : UInt32
end
```

We use `property` (or `getter`) to generate accessors. Constructors are provided for convenience, but they are not used when the structure is filled by libpcap; they are only used when we create instances ourselves (e.g., for writing).

## 3. Callbacks and the Box

`pcap_loop` and `pcap_dispatch` accept a C function pointer. In Crystal, we use a `Proc` that matches the C signature:

```crystal
alias PcapHandler = (UInt8*, PcapPkthdr*, UInt8*) -> Void
```

To pass a Crystal block, we use `Box` to store the block in a heap‑allocated object and pass its pointer as the `user` argument. The C callback then `unbox`es the block and calls it.

```crystal
boxed = Box.box(->(hdr : PcapPkthdr*, bytes : Bytes) { ... })
callback = ->(user : UInt8*, hdr : PcapPkthdr*, data : UInt8*) {
  box = Box(CrystalPacketHandler).unbox(user.as(Void*))
  bytes = Bytes.new(data, hdr.value.caplen)
  box.call(hdr, bytes)
}
LibPcap::C.loop(@ptr, count, callback, boxed.as(UInt8*))
```

We keep the `boxed` pointer alive in `@callback_box` to prevent garbage collection while the loop runs.

## 4. Resource Management (RAII)

Each handle (PcapHandle, PcapDumper) holds a C pointer. We provide:

- `#close` – explicit cleanup.
- `#finalize` – a finalizer that calls `pcap_close` or `pcap_dump_close` when the object is garbage‑collected.

This ensures resources are freed even if the user forgets to close.

```crystal
def finalize
    close
end
```

## 5. Error Handling

Libpcap functions return error codes or `NULL` pointers. We translate these into Crystal exceptions:

- `pcap_geterr` is used to obtain a descriptive error string.
- Exceptions are raised with the error message.

For functions like `pcap_next_ex` that return multiple states (`OK`, `EOF`, `ERROR`), we use the `Result(T)` type to capture the outcome.

## 6. Optional Features (Compilation Flags)

Some _libpcap_ functions are not available on all systems. We guard them with `{% if flag?(:remote) %}` and `{% if flag?(:protocol) %}`.

- `-D remote` enables `pcap_open` (remote capture).
- `-D protocol` enables `pcap_set_protocol` (Linux‑specific).

These flags must be passed at compile time, e.g., `crystal build -D remote`.

## 7. Testing

The _spec suite_ is located in `spec/`. Live‑device tests are guarded by environment variables (`TEST_LIVE=1`, `TEST_REMOTE=1`) to avoid failing in CI environments without proper interfaces. They use helper functions to obtain a handle (trying devices until one works).

## 8. Extending the Bindings

To add a new libpcap function:

- Declare the function in `src/libpcap/lib/lib_pcap.cr` inside the lib C block.
- If it uses a new C struct, define it in `structs.cr`.
- Add a high‑level wrapper method in the appropriate class (usually `PcapHandle`).
- Write a spec test for the new functionality.
- Update the documentation (README, guide, API reference).

Always consider resource management and error handling.

## 9. Memory Safety

- Pointers are checked for `null` before use.
- We avoid manual pointer arithmetic; use `Bytes` for safe memory access.
- The `Box` mechanism ensures that callbacks do not outlive the associated Crystal objects (the box is kept alive by `@callback_box`).

10. Cross‑Platform Considerations

- Address families like `AF_PACKET` (Linux) are handled gracefully: `Socket::Address.from` may fail, but we rescue and return `nil`.
- The `any` pseudo‑device fallback is Linux‑specific; on other systems, the library will raise if no real device is usable.
- Some functions (like `pcap_set_protocol`) are only available on Linux; they are optional.

11. Performance Optimisations

- Lazy parsing: packet headers are only parsed when accessed.
- Minimal allocation: `Bytes` slices are used without copying.
- The callback path is efficient, avoiding extra allocations per packet.

12. Future Enhancements

**Potential additions**:

- Support for reading/writing pcap‑ng (though libpcap already handles it).
- Full pcap‑ng block iteration.
- More sophisticated timestamp handling.
- Platform‑specific optimisations (e.g., Linux AF_PACKET rings).

Contributions are welcome!
