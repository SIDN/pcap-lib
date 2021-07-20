package nl.sidnlabs.pcap.decoder;

import nl.sidnlabs.pcap.PcapReader;
import nl.sidnlabs.pcap.packet.Packet;

public interface Decoder {

  int PROTOCOL_HEADER_SRC_PORT_OFFSET = 0;
  int PROTOCOL_HEADER_DST_PORT_OFFSET = 2;

  Packet reassemble(Packet packet, byte[] packetData);

  default boolean isDNS(Packet packet) {
    return packet.getSrcPort() == PcapReader.DNS_PORT || packet.getDstPort() == PcapReader.DNS_PORT;
  }

  void printStats();

  void reset();
}
