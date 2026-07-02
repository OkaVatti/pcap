# src/libpcap.cr
require "./libpcap/version"
require "./libpcap/lib/lib_pcap"
require "./libpcap/error/error"
require "./libpcap/capture/device"
require "./libpcap/capture/handle"
require "./libpcap/packet/packet"
require "./libpcap/packet/ethernet"
require "./libpcap/packet/ipv4"
require "./libpcap/packet/tcp"
require "./libpcap/packet/udp"
require "./libpcap/savefile/dumper"
require "./libpcap/savefile/writer"
require "./libpcap/savefile/reader"

# The main namespace for all libpcap functionality.
module LibPcap
  # A convenient alias for the version string.
  def self.version : String
    String.new(LibPcap::C.lib_version)
  end

  # Initialise libpcap globally (optional).
  # Usually not needed, but provided for completeness.
  def self.init(optimization : Int32 = 0) : Nil
    rc = LibPcap::C.init(optimization)
    if rc != 0
      raise Error.new("pcap_init failed with code #{rc}")
    end
  end

  # Open a savefile for reading.
  def self.open_offline(path : String) : SavefileReader
    SavefileReader.new(path)
  end

  # Create a savefile writer.
  def self.create_writer(handle : PcapHandle, filename : String) : SavefileWriter
    SavefileWriter.new(handle, filename)
  end
end
