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

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;
import com.google.common.primitives.Bytes;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import nl.sidnlabs.pcap.PcapReaderUtil;
import nl.sidnlabs.pcap.packet.DNSPacket;
import nl.sidnlabs.pcap.packet.Datagram;
import nl.sidnlabs.pcap.packet.DatagramPayload;
import nl.sidnlabs.pcap.packet.ICMPPacket;
import nl.sidnlabs.pcap.packet.Packet;
import nl.sidnlabs.pcap.packet.PacketFactory;
import nl.sidnlabs.pcap.util.IPv4Util;
import nl.sidnlabs.pcap.util.IPv6Util;

/**
 * Decode the IP header
 *
 */
@Data
@Log4j2
public class IPDecoder {

  public static final int IP_PROTOCOL_VERSION_4 = 4;
  public static final int IP_PROTOCOL_VERSION_6 = 6;
  public static final int IP_TOTAL_LEN_OFFSET = 2; // relative to start of IP header
  public static final int IP_FLAGS = 6;
  public static final int IP_FRAGMENT_OFFSET = 6; // The first 3 bits are the flags

  private Multimap<Datagram, DatagramPayload> datagrams = TreeMultimap.create();

  private Decoder tcpReader;
  private Decoder udpReader;
  private ICMPDecoder icmpDecoder;


  public IPDecoder(Decoder tcpReader, Decoder udpReader, ICMPDecoder icmpDecoder) {
    this.tcpReader = tcpReader;
    this.udpReader = udpReader;
    this.icmpDecoder = icmpDecoder;
  }

  public void printStats() {
    udpReader.printStats();
    if (tcpReader != null) {
      tcpReader.printStats();
    }
    icmpDecoder.printStats();
  }

  public Packet decode(byte[] packetData, int ipStart, long packetTimestampSecs,
      long packetTimestampMicros) {

    if (ipStart == -1)
      return Packet.NULL;

    Packet p = createPacket(packetData, ipStart);

    p.setTsSec(packetTimestampSecs);
    p.setTsMicro(packetTimestampMicros);
    // calc the timestamp in milliseconds = seconds + micros combined
    p.setTsMilli((packetTimestampSecs * 1000) + Math.round(packetTimestampMicros / 1000f));

    return decode(p, packetData, ipStart);
  }

  private Packet decode(Packet packet, byte[] packetData, int ipStart) {

    int ipProtocolHeaderVersion = IPv4Util.getInternetProtocolHeaderVersion(packetData, ipStart);
    packet.setIpVersion(ipProtocolHeaderVersion);

    int totalLength = 0;
    if (ipProtocolHeaderVersion == IP_PROTOCOL_VERSION_4) {
      int ipHeaderLen = IPv4Util.getInternetProtocolHeaderLength(packetData, ipStart);
      packet.setIpHeaderLen(ipHeaderLen);
      packet.setTtl(IPv4Util.decodeTTL(packetData, ipStart));
      packet.setSrc(IPv4Util.decodeSrc(packetData, ipStart));
      packet.setDst(IPv4Util.decodeDst(packetData, ipStart));
      packet.setIpId(IPv4Util.decodeId(packetData, ipStart));
      totalLength = PcapReaderUtil.convertShort(packetData, ipStart + IP_TOTAL_LEN_OFFSET);
      decodeV4Fragmented(packet, ipStart, packetData);
    } else {
      int ipHeaderLen = IPv6Util.getInternetProtocolHeaderLength(packetData, ipStart);
      packet.setIpHeaderLen(ipHeaderLen);
      packet.setTtl(IPv6Util.decodeTTL(packetData, ipStart));
      packet.setSrc(IPv6Util.decodeSrc(packetData, ipStart));
      packet.setDst(IPv6Util.decodeDst(packetData, ipStart));
      packet.setIpId(IPv6Util.decodeId(packetData, ipStart));
      int payloadLength =
          PcapReaderUtil.convertShort(packetData, ipStart + IPv6Util.IPV6_PAYLOAD_LEN_OFFSET);
      totalLength = payloadLength + IPv6Util.IPV6_HEADER_SIZE;

      decodeV6Fragmented(packet, ipStart, packetData);
      // v6 last frag is field in extension header
      if (packet.isFragmented()) {
        IPv6Util.buildInternetProtocolV6ExtensionHeaderFragment(packet, packetData, ipStart);
      }
    }

    packet.setTotalLength(totalLength);
    // check for presence of ethernet padding, eth frames must be minumum of 64bytes
    // and eth adapters can add padding to get 64 byte packet size
    int padding = Math.max(packetData.length - (totalLength + ipStart), 0);

    /*
     * Copy the IP payload into a packetData. Make sure there is no ethernet padding present. see:
     * https://wiki.wireshark.org/Ethernet padding present, copy all data except the padding, to
     * avoid problems decoding tcp/udp/dns
     */
    packetData = Arrays
        .copyOfRange(packetData, ipStart + packet.getIpHeaderLen(), packetData.length - padding);

    byte[] reassembledData = reassemble(packet, packetData);
    // if reassembledData is empty then the IP packet is fragmented and the current packet is not
    // yet the final fragment
    if (reassembledData.length == 0) {
      return Packet.NULL;
    }

    return handlePayload(packet, reassembledData);
  }


  public Packet createPacket(byte[] packetData, int ipStart) {
    int ipProtocolHeaderVersion = IPv4Util.getInternetProtocolHeaderVersion(packetData, ipStart);
    byte protocol = -1;

    if (ipProtocolHeaderVersion == IP_PROTOCOL_VERSION_4) {
      protocol = IPv4Util.decodeProtocol(packetData, ipStart);
    } else if (ipProtocolHeaderVersion == IP_PROTOCOL_VERSION_6) {
      protocol = IPv6Util.decodeProtocol(packetData, ipStart);
    } else {
      log.error("Unsupported IP version " + ipProtocolHeaderVersion + " ipstart=" + ipStart);
      return Packet.NULL;
    }
    return PacketFactory.create(protocol);
  }

  private Packet handlePayload(Packet packet, byte[] packetData) {

    if ((PacketFactory.PROTOCOL_ICMP_V4 == packet.getProtocol())
        || (PacketFactory.PROTOCOL_ICMP_V6 == packet.getProtocol())) {

      // found icmp protocol
      icmpDecoder.reassemble((ICMPPacket) packet, packetData);
      // do not process icmp packet further, because the dns packet might be corrupt (only 8 bytes
      // in icmp packet)
      return packet;
    }

    if (PacketFactory.PROTOCOL_TCP == packet.getProtocol()) {
      // found TCP protocol
      if (tcpReader == null) {
        // tcp not enabled
        return Packet.NULL;
      }
      packet = tcpReader.reassemble(packet, packetData);
    } else if (PacketFactory.PROTOCOL_UDP == packet.getProtocol()) {
      // found UDP protocol
      packet = udpReader.reassemble(packet, packetData);
    }

    if (packet instanceof DNSPacket && ((DNSPacket) packet).getMessageCount() == 0) {
      // no dns message(s) found
      return Packet.NULL;
    }

    return packet;
  }

  private void decodeV6Fragmented(Packet packet, int ipStart, byte[] packetData) {
    // assumption that the first extension header is the fragmentation header
    int nxtHdr = packetData[ipStart + IPv6Util.IPV6_NEXTHEADER_OFFSET];
    packet.setFragmented(nxtHdr == IPv6Util.IPV6_FRAGMENT_EXTENTION_TYPE);
  }

  private void decodeV4Fragmented(Packet packet, int ipStart, byte[] packetData) {
    long fragmentOffset =
        (PcapReaderUtil.convertShort(packetData, ipStart + IP_FRAGMENT_OFFSET) & 0x1FFF) * 8L;
    packet.setFragOffset(fragmentOffset);

    // get flag bits from ip header
    int flags = packetData[ipStart + IP_FLAGS] & 0xE0;

    if ((flags & 0x40) == 0x40) {
      // bit 1 of flags is set
      packet.setDoNotFragment(true);
    } else if ((flags & 0x20) == 0x20 || fragmentOffset != 0) {
      // bit 2 of flags is set
      packet.setFragmented(true);
      packet.setLastFragment(((flags & 0x20) == 0 && fragmentOffset != 0));
    }

  }

  /**
   * Reassemble the IP packet is it is fragmented. If it is not fragmented then the packetData bytes
   * are returned as result. If the packet is fragmented and this packet is the final fragment then
   * all the bytes from the fragments are concatenated and returned. if fragmented and current
   * fragment is not yet the final fragment then an empty byte array is returned. the
   * 
   * @param packet the current packet
   * @param packetData the payload of the current packet
   * @return input, reassembled or no bytes
   */
  public byte[] reassemble(Packet packet, byte[] packetData) {

    if (!packet.isFragmented()) {
      return packetData;
    }

    Datagram datagram = packet.getDatagram();
    DatagramPayload payload = new DatagramPayload(packet.getFragOffset(), packetData);
    datagrams.put(datagram, payload);

    if (packet.isLastFragment()) {
      byte[] reassembledPacketData = new byte[0];
      // reassemble IP fragments
      Collection<DatagramPayload> datagramPayloads = datagrams.removeAll(datagram);
      if (datagramPayloads != null && !datagramPayloads.isEmpty()) {
        int reassembledFragments = 0;
        DatagramPayload prev = null;
        for (DatagramPayload datagramPayload : datagramPayloads) {
          if (prev == null && datagramPayload.getOffset() != 0) {
            if (log.isDebugEnabled()) {
              log
                  .debug(
                      "Datagram chain not starting at 0. Probably received packets out-of-order. Can't reassemble this packet.");
            }
            // do not even try to reassemble the data, probably corrupt packets.
            return new byte[0];
          }
          if (prev != null && !datagramPayload.linked(prev)) {
            if (log.isDebugEnabled()) {
              log
                  .debug("Broken datagram chain between " + datagramPayload + " and " + prev
                      + ". Can't reassemble this packet.");
            }
            // do not even try to reassemble the data, probably corrupt packets.
            return new byte[0];
          }
          reassembledPacketData = Bytes.concat(reassembledPacketData, datagramPayload.getPayload());
          reassembledFragments++;
          prev = datagramPayload;
        }
        packet.setReassembledFragments(reassembledFragments);
      }

      return reassembledPacketData;
    }

    // need final IP fragment before continu to tcp/udp reassembly
    // until then return empty byte array
    return new byte[0];
  }

  public Multimap<Datagram, DatagramPayload> getDatagrams() {
    return datagrams;
  }

  public void setDatagrams(Multimap<Datagram, DatagramPayload> datagrams) {
    this.datagrams = datagrams;
  }

  /**
   * Clear expired cache entries in order to avoid memory problems
   * 
   * @param ipFragmentTTL timeout for IP fragments
   */
  public void clearCache(int ipFragmentTTL) {
    long now = System.currentTimeMillis();
    // check IP datagrams
    List<Datagram> dgExpiredList = datagrams
        .keySet()
        .stream()
        .filter(k -> (k.getTime() + ipFragmentTTL) <= now)
        .collect(Collectors.toList());

    log.info("IP datagram cache size: " + datagrams.size());
    log.info("Expired (to be removed) IP datagrams: " + dgExpiredList.size());

    // remove expired IP datagrams
    dgExpiredList.stream().forEach(dg -> datagrams.removeAll(dg));
  }
}
