require "../../spec_helper"

describe LibPcap::PcapHandle do
  it "creates a dead handle" do
    handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
    handle.should be_a(LibPcap::PcapHandle)
    handle.close
  end

  it "opens and reads from a synthetic pcap file" do
    path = create_test_pcap
    handle = LibPcap::PcapHandle.for_offline(path)
    handle.datalink.should eq(LibPcap::DLT_EN10MB)

    # Use unwrap! to get the packet or raise on EOF/error
    packet = handle.next_packet.unwrap!
    packet.should be_a(LibPcap::Packet)
    packet.data.size.should eq(64) # eth14+ip20+tcp20+payload10 = 64

    # Second packet should be EOF
    result = handle.next_packet
    result.eof?.should be_true

    handle.close
    File.delete(path)
  end

  it "applies a BPF filter" do
    path = create_test_pcap
    handle = LibPcap::PcapHandle.for_offline(path)
    handle.filter = "tcp"
    # It should not raise. We can try to read a packet – it should match.
    packet = handle.next_packet.unwrap!
    packet.should be_a(LibPcap::Packet)
    handle.close
    File.delete(path)
  end

  it "raises on invalid filter" do
    handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
    expect_raises(LibPcap::FilterError) do
      handle.filter = "invalid filter syntax"
    end
    handle.close
  end

  it "can use loop on offline file" do
    path = create_test_pcap
    handle = LibPcap::PcapHandle.for_offline(path)
    count = 0
    handle.loop(count: 5) do |_|
      count += 1
    end
    count.should eq(1) # only one packet in the file
    handle.close
    File.delete(path)
  end
end
