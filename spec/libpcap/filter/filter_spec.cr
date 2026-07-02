require "../../spec_helper"

describe "BPF filters" do
  it "compiles and sets a filter on an offline handle" do
    path = create_test_pcap
    handle = LibPcap::PcapHandle.for_offline(path)
    handle.filter = "tcp"
    # Should not raise.
    packet = handle.next_packet.unwrap!
    packet.should be_a(LibPcap::Packet)
    handle.close
    File.delete(path)
  end

  it "rejects invalid filter expressions" do
    handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
    expect_raises(LibPcap::FilterError) do
      handle.filter = "invalid"
    end
    handle.close
  end
end
