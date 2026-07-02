require "../../spec_helper"

describe LibPcap::SavefileWriter do
  it "writes and reads a packet" do
    temp = File.tempfile("test.pcap")
    path = temp.path
    temp.close

    handle = LibPcap::PcapHandle.dead(LibPcap::DLT_EN10MB)
    writer = LibPcap::SavefileWriter.new(handle, path)

    # Get a packet from a synthetic file
    synth_path = create_test_pcap
    synth_handle = LibPcap::PcapHandle.for_offline(synth_path)
    packet = synth_handle.next_packet.unwrap!

    # Write the packet using the writer
    writer.write(packet)
    writer.close
    synth_handle.close
    File.delete(synth_path)

    # Read back
    reader = LibPcap::SavefileReader.new(path)
    count = 0
    reader.each_packet do |p|
      count += 1
      p.len.should eq(packet.len)
      p.timestamp.should eq(packet.timestamp)
    end
    count.should eq(1)
    reader.close

    File.delete(path)
  end

  it "capture_loop writes packets" do
    temp = File.tempfile("test.pcap")
    path = temp.path
    temp.close

    synth_path = create_test_pcap
    handle = LibPcap::PcapHandle.for_offline(synth_path)
    writer = LibPcap::SavefileWriter.new(handle, path)

    count = 0
    writer.capture_loop do |packet|
      count += 1
      false
    end
    count.should eq(1)
    writer.close
    handle.close

    reader = LibPcap::SavefileReader.new(path)
    count2 = 0
    reader.each_packet { count2 += 1 }
    count2.should eq(1)
    reader.close

    File.delete(path)
    File.delete(synth_path)
  end
end
