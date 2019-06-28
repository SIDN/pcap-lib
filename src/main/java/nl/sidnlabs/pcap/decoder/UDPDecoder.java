/*
 * ENTRADA, a big data platform for network data analytics
 *
 * Copyright (C) 2016 SIDN [https://www.sidn.nl]
 * 
 * This file is part of ENTRADA.
 * 
 * ENTRADA is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * ENTRADA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with ENTRADA. If
 * not, see [<http://www.gnu.org/licenses/].
 *
 */
package nl.sidnlabs.pcap.decoder;

import lombok.Data;
import lombok.extern.log4j.Log4j2;
import nl.sidnlabs.pcap.PcapReader;
import nl.sidnlabs.pcap.PcapReaderUtil;
import nl.sidnlabs.pcap.packet.DNSPacket;
import nl.sidnlabs.pcap.packet.Packet;
import nl.sidnlabs.pcap.util.UDPUtil;

/**
 * Decode UDP packets
 *
 */
@Log4j2
@Data
public class UDPDecoder implements PacketReader {


  private DNSDecoder dnsDecoder = new DNSDecoder();

  /**
   * Decode the udp packet, supports reassembly of fragmented packets
   * 
   * @param packet
   * @param packetData
   * @return payload bytes or null if not a valid packet
   */
  @Override
  public Packet reassemble(Packet packet, byte[] packetData, int offset) {

    // if the offset == 0 then the payload contains the udp header, do not read the header, only get
    // the udp payload bytes

    packet
        .setSrcPort(PcapReaderUtil
            .convertShort(packetData,
                offset + packet.getIpHeaderLen() + PcapReader.PROTOCOL_HEADER_SRC_PORT_OFFSET));
    packet
        .setDstPort(PcapReaderUtil
            .convertShort(packetData,
                offset + packet.getIpHeaderLen() + PcapReader.PROTOCOL_HEADER_DST_PORT_OFFSET));

    if (packet.getIpVersion() == 4) {
      int cksum = UDPUtil.getUdpChecksum(packetData, offset, packet.getIpHeaderLen());
      if (cksum >= 0) {
        packet.setUdpsum(cksum);
      }
    }

    // int payloadDataStart = offset + packet.getIpHeaderLen() + UDPUtil.UDP_HEADER_SIZE;
    // int payloadLength = packetData.length - packet.getIpHeaderLen() - UDPUtil.UDP_HEADER_SIZE;
    byte[] packetPayload = decode(packet, packetData, offset);
    // PcapReaderUtil.readPayload(packetData, payloadDataStart, payloadLength);

    // total length of packet, might be wrong if icmp truncation is in play
    packet.setUdpLength(packetData.length);
    packet.setPayloadLength(UDPUtil.getUdpLen(packetData, offset, packet.getIpHeaderLen()));


    if (packet.getFragOffset() == 0 && packet.getSrcPort() != PcapReader.DNS_PORT
        && packet.getDstPort() != PcapReader.DNS_PORT) {
      // not a dns packet
      packetPayload = new byte[0];
    }

    if (!isDNS(packet)) {
      // not a dns packet
      if (log.isDebugEnabled()) {
        log.debug("Packet is not a DNS packet: " + packet);
      }
      return Packet.NULL;
    }

    if (packetPayload.length == 0) {
      // no DNS packets found
      if (log.isDebugEnabled()) {
        log.debug("No valid DNS packet found: " + packet);
      }
      return Packet.NULL;
    }


    DNSPacket dnsPacket = (DNSPacket) packet;
    try {
      return dnsDecoder.decode(dnsPacket, packetPayload);
    } catch (Exception e) {
      /*
       * catch anything which might get thrown out of the dns decoding if the tcp bytes are somehow
       * incorrectly assembled the dns decoder will fail.
       * 
       * ignore the error and skip the packet.
       */
      if (log.isDebugEnabled()) {
        log.debug("Packet payload could not be decoded (malformed packet?) details: " + packet);
      }
    }
    return Packet.NULL;
  }

  public byte[] decode(Packet packet, byte[] packetData, int offset) {
    int payloadDataStart = offset + packet.getIpHeaderLen() + UDPUtil.UDP_HEADER_SIZE;
    int payloadLength = packetData.length - packet.getIpHeaderLen() - UDPUtil.UDP_HEADER_SIZE;

    return PcapReaderUtil.readPayload(packetData, payloadDataStart, payloadLength);
  }
}
