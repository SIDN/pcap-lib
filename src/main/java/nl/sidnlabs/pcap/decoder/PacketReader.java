package nl.sidnlabs.pcap.decoder;

import nl.sidnlabs.pcap.PcapReader;
import nl.sidnlabs.pcap.packet.Packet;

public interface PacketReader {

  Packet reassemble(Packet packet, byte[] packetData, int offset);

  default boolean isDNS(Packet packet) {
    return packet.getFragOffset() == 0 && (packet.getSrcPort() == PcapReader.DNS_PORT
        || packet.getDstPort() == PcapReader.DNS_PORT);
  }

}
