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

import lombok.Getter;
import lombok.Setter;
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
@Getter
@Setter
public class UDPDecoder implements Decoder {

  private DNSDecoder dnsDecoder;
  private int packetCounter = 0;
  private int reqCounter = 0;
  private int respCounter = 0;

  public UDPDecoder(DNSDecoder dnsDecoder) {
    this.dnsDecoder = dnsDecoder;
  }


  /**
   * Decode the udp packet, supports reassembly of fragmented packets
   * 
   * @param packet the packet to reassemble
   * @param packetData bytes to decode
   * @return payload bytes or null if not a valid packet
   */
  @Override
  public Packet reassemble(Packet packet, byte[] packetData) {
    packetCounter++;

    packet
        .setSrcPort(
            PcapReaderUtil.convertShort(packetData, Decoder.PROTOCOL_HEADER_SRC_PORT_OFFSET));
    packet
        .setDstPort(
            PcapReaderUtil.convertShort(packetData, Decoder.PROTOCOL_HEADER_DST_PORT_OFFSET));

    if (!isDNS(packet)) {
      // not a dns packet
      if (log.isDebugEnabled()) {
        log.debug("Packet is not a DNS packet: " + packet);
      }
      return Packet.NULL;
    }

    byte[] packetPayload = decode(packetData);
    if (packetPayload.length == 0) {
      // no DNS packets found
      if (log.isDebugEnabled()) {
        log.debug("No valid DNS packet found: " + packet);
      }
      return Packet.NULL;
    }

    if (packet.getDstPort() == PcapReader.DNS_PORT) {
      reqCounter++;
    } else {
      respCounter++;
    }

    // total length of packet, might be wrong if icmp truncation is in play
    packet.setLen(packetData.length);
    packet.setPayloadLength(UDPUtil.getUdpLen(packetData));

    return dnsDecoder.decode((DNSPacket) packet, packetPayload, 0, packetPayload.length);
  }

  public byte[] decode(byte[] packetData) {
    int payloadLength = packetData.length - UDPUtil.UDP_HEADER_SIZE;
    return PcapReaderUtil.readPayload(packetData, UDPUtil.UDP_HEADER_SIZE, payloadLength);
  }


  public void printStats() {
    log.info("------------- UDP Decoder Stats --------------------------");
    log.info("Packets: {}", Integer.valueOf(packetCounter));
    log.info("Requests: {}", Integer.valueOf(reqCounter));
    log.info("Responses: {}", Integer.valueOf(respCounter));
  }

  @Override
  public void reset() {
    packetCounter = 0;
    reqCounter = 0;
    respCounter = 0;

    dnsDecoder.reset();
  }
}
