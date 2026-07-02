require "../../spec_helper"

private def root? : Bool
  LibC.getuid == 0
end

# Helper: create an empty pcap file (no packets)
def create_empty_pcap : String
  temp = File.tempfile("empty_", ".pcap")
  path = temp.path
  temp.close

  io = IO::Memory.new
  io.write_bytes(0xa1b2c3d4_u32, IO::ByteFormat::LittleEndian)
  io.write_bytes(2_u16, IO::ByteFormat::LittleEndian)
  io.write_bytes(4_u16, IO::ByteFormat::LittleEndian)
  io.write_bytes(0_u32, IO::ByteFormat::LittleEndian)
  io.write_bytes(0_u32, IO::ByteFormat::LittleEndian)
  io.write_bytes(65535_u32, IO::ByteFormat::LittleEndian)
  io.write_bytes(1_u32, IO::ByteFormat::LittleEndian) # DLT_EN10MB

  File.write(path, io.to_slice)
  path
end

# Helper: obtain an activated live handle.
# Tries all real devices; if none work, tries the "any" pseudo-device (Linux).
private def get_live_handle : LibPcap::PcapHandle
  devices = LibPcap::Device.all

  # Try each real device
  devices.each do |device|
    handle = LibPcap::PcapHandle.for_live(device)
    handle.snaplen = 65536
    handle.timeout_ms = 100
    begin
      handle.activate
      return handle
    rescue LibPcap::ActivationError
      # Device not usable, close and continue
      handle.close
    end
  end

  # Fallback: try the "any" pseudo-device (common on Linux)
  begin
    handle = LibPcap::PcapHandle.for_live("any")
    handle.snaplen = 65536
    handle.timeout_ms = 100
    handle.activate
    handle
  rescue
    # If all fail, raise a clear error
    raise "No usable network interface found for live capture"
  end
end

describe "Advanced features" do
  describe "timestamp precision" do
    it "can get precision on an offline handle" do
      path = create_test_pcap
      handle = LibPcap::PcapHandle.for_offline(path)
      handle.tstamp_precision.should eq(LibPcap::PCAP_TSTAMP_PRECISION_MICRO)
      handle.close
      File.delete(path)
    end

    it "can open with nano precision" do
      path = create_test_pcap
      handle = LibPcap::PcapHandle.for_offline_with_precision(path, LibPcap::PCAP_TSTAMP_PRECISION_NANO)
      handle.tstamp_precision.should eq(LibPcap::PCAP_TSTAMP_PRECISION_NANO)
      handle.close
      File.delete(path)
    end

    it "cannot set precision after activation (raises)" do
      path = create_test_pcap
      handle = LibPcap::PcapHandle.for_offline(path)
      expect_raises(LibPcap::ConfigurationError) do
        handle.tstamp_precision = LibPcap::PCAP_TSTAMP_PRECISION_NANO
      end
      handle.close
      File.delete(path)
    end
  end

  describe "non‑blocking mode" do
    it "sets and gets non‑blocking mode on a live handle" do
      handle = get_live_handle

      handle.nonblock?.should be_false
      handle.nonblock = true
      handle.nonblock?.should be_true
      handle.nonblock = false
      handle.nonblock?.should be_false

      handle.close
    end

    it "returns selectable_fd on a live handle" do
      handle = get_live_handle

      fd = handle.selectable_fd
      fd.should_not be_nil
      fd.as(Int32).should be >= 0

      handle.close
    end

    it "raises on invalid non‑blocking set on a dead handle" do
      handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
      expect_raises(LibPcap::Error) do
        handle.nonblock = true
      end
      handle.close
    end
  end

  describe "direction control" do
    it "sets direction on a live handle" do
      handle = get_live_handle

      handle.direction = LibPcap::PCAP_D_INOUT
      handle.direction = LibPcap::PCAP_D_IN
      handle.direction = LibPcap::PCAP_D_OUT

      handle.close
    end

    it "raises on direction set on a dead handle" do
      handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
      expect_raises(LibPcap::ConfigurationError) do
        handle.direction = LibPcap::PCAP_D_IN
      end
      handle.close
    end
  end

  describe "list of datalink types" do
    it "returns a non‑empty array on a live handle" do
      handle = get_live_handle

      types = handle.datalink_types
      types.should be_a(Array(Int32))
      types.should_not be_empty
      types.should contain(handle.datalink)

      handle.close
    end

    it "works on an offline handle (returns at least current datalink)" do
      path = create_test_pcap
      handle = LibPcap::PcapHandle.for_offline(path)
      types = handle.datalink_types
      types.should be_a(Array(Int32))
      types.should contain(handle.datalink)
      handle.close
      File.delete(path)
    end
  end

  describe "packet injection" do
    it "raises on injection on a dead handle" do
      handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
      data = Bytes.new(14, 0)
      expect_raises(LibPcap::Error) do
        handle.inject(data)
      end
      handle.close
    end

    it "injects a packet on a live handle (adapts to permissions)" do
      handle = get_live_handle
      data = Bytes.new(14, 0xAA)

      if root?
        sent = handle.inject(data)
        sent.should eq(data.size)
      else
        # Without root, injection should fail with an error
        expect_raises(LibPcap::Error) do
          handle.inject(data)
        end
      end

      handle.close
    end
  end

  describe "dispatch" do
    it "processes packets similarly to loop on an offline file" do
      path = create_test_pcap
      handle = LibPcap::PcapHandle.for_offline(path)

      loop_count = 0
      handle.loop(count: 1) do |_|
        loop_count += 1
      end

      dispatch_count = 0
      handle2 = LibPcap::PcapHandle.for_offline(path)
      handle2.dispatch(count: 1) do |_|
        dispatch_count += 1
      end
      dispatch_count.should eq(loop_count)

      handle.close
      handle2.close
      File.delete(path)
    end

    it "returns immediately if no packets (with count=0)" do
      path = create_empty_pcap
      handle = LibPcap::PcapHandle.for_offline(path)
      count = 0
      handle.dispatch(count: 0) do |_|
        count += 1
      end
      count.should eq(0)
      handle.close
      File.delete(path)
    end
  end

  describe "dump flush" do
    it "does not raise on flush" do
      temp = File.tempfile("test_dump", ".pcap")
      path = temp.path
      temp.close

      handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
      writer = LibPcap::SavefileWriter.new(handle, path)
      writer.dumper.flush
      writer.close
      handle.close

      File.delete(path)
    end
  end

  # ---- New tests for missing features ----
  describe "timestamp types" do
    it "lists timestamp types on a live handle" do
      handle = get_live_handle
      types = handle.tstamp_types
      types.should be_a(Array(Int32))
      types.should_not be_empty
      handle.close
    end

    it "sets a valid timestamp type" do
      handle = get_live_handle
      types = handle.tstamp_types
      unless types.empty?
        begin
          handle.tstamp_type = types.first
        rescue LibPcap::ConfigurationError
          # Some interfaces do not support setting timestamp types
          # even though they are listed; we skip the assertion.
        end
      end
      handle.close
    end
  end

  {% if flag?(:protocol) %}
    describe "protocol setting" do
      it "does not raise when setting protocol (if supported)" do
        handle = get_live_handle
        begin
          handle.protocol = LibPcap::PCAP_PROTOCOL_ETHERNET
        rescue LibPcap::ConfigurationError
          # Ignore; may fail if protocol not supported
        end
        handle.close
      end
    end
  {% end %}

  describe "statustostr" do
    it "returns a non‑empty string for a valid error code" do
      str = LibPcap::PcapHandle.statustostr(0)
      str.should be_a(String)
      str.should_not be_empty
    end
  end

  describe "dump append" do
    it "can open a dumper in append mode (if supported)" do
      # Create a temporary file with one packet
      temp = File.tempfile("append_test", ".pcap")
      path = temp.path
      temp.close

      handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
      dumper = handle.open_dumper(path)

      # Write a dummy packet with a proper header
      data = Bytes.new(14, 0xAA)
      now = Time.utc
      ts = LibC::Timeval.new
      ts.tv_sec = now.to_unix
      ts.tv_usec = now.nanosecond // 1000
      header = LibPcap::PcapPkthdr.new(
        ts: ts,
        caplen: data.size.to_u32,
        len: data.size.to_u32
      )
      dumper.dump(pointerof(header), data)
      dumper.close

      # Try to open in append mode
      begin
        dumper2 = handle.open_dumper_append(path)
        dumper2.close
      rescue LibPcap::DumperError
        # Append mode may not be supported; skip
      end

      handle.close
      File.delete(path)
    end
  end

  {% if flag?(:remote) %}
    describe "remote capture" do
      it "can be opened if a remote server is available" do
        if ENV["TEST_REMOTE"]? == "1"
          source = ENV["TEST_REMOTE_SOURCE"]? || "rpcap://localhost/eth0"
          handle = LibPcap::PcapHandle.for_remote(source, snaplen: 65536, flags: LibPcap::PCAP_OPENFLAG_PROMISCUOUS)
          handle.should be_a(LibPcap::PcapHandle)
          handle.close
        else
          pending "Remote capture tests skipped (set TEST_REMOTE=1 and TEST_REMOTE_SOURCE to run)"
        end
      end

      it "raises on invalid remote source" do
        expect_raises(LibPcap::OpenError) do
          LibPcap::PcapHandle.for_remote("rpcap://invalidhost/invalid")
        end
      end
    end
  {% end %}
end
