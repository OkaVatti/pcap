require "../../spec_helper"

describe LibPcap::Packet do
  it "parses Ethernet header" do
    path = create_test_pcap
    handle = LibPcap::PcapHandle.for_offline(path)
    packet = handle.next_packet.unwrap!

    eth = packet.ethernet
    eth.dst_mac.should eq("00:11:22:33:44:55")
    eth.src_mac.should eq("66:77:88:99:aa:bb")
    eth.ethertype.should eq(0x0800)
    eth.payload.size.should eq(packet.data.size - 14)

    handle.close
    File.delete(path)
  end

  it "parses IPv4 header" do
    path = create_test_pcap
    handle = LibPcap::PcapHandle.for_offline(path)
    packet = handle.next_packet.unwrap!

    ip = packet.ipv4
    ip.version.should eq(4)
    ip.header_len.should eq(20)
    ip.tos.should eq(0)
    ip.total_len.should eq(40)
    ip.ttl.should eq(64)
    ip.protocol.should eq(6) # TCP
    ip.src_ip.should eq("192.168.1.1")
    ip.dst_ip.should eq("192.168.1.2")

    handle.close
    File.delete(path)
  end

  it "parses TCP header" do
    path = create_test_pcap
    handle = LibPcap::PcapHandle.for_offline(path)
    packet = handle.next_packet.unwrap!

    tcp = packet.tcp
    tcp.src_port.should eq(80)
    tcp.dst_port.should eq(0)
    tcp.syn?.should be_true
    tcp.ack?.should be_false
    tcp.header_len.should eq(20)
    tcp.payload.size.should eq(10)

    handle.close
    File.delete(path)
  end

  it "raises on invalid Ethernet" do
    data = Bytes.new(10, 0)
    expect_raises(LibPcap::Error) { LibPcap::EthernetHeader.new(data) }
  end
end
