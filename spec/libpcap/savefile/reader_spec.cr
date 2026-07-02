require "../../spec_helper"

describe LibPcap::SavefileReader do
  it "iterates over packets" do
    path = create_test_pcap
    reader = LibPcap::SavefileReader.new(path)
    count = 0
    reader.each_packet do |packet|
      count += 1
      packet.should be_a(LibPcap::Packet)
    end
    count.should eq(1)
    reader.close
    File.delete(path)
  end
end
