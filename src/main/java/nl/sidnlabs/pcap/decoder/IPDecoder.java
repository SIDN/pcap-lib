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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;
import com.google.common.primitives.Bytes;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import nl.sidnlabs.pcap.PcapReaderUtil;
import nl.sidnlabs.pcap.SequencePayload;
import nl.sidnlabs.pcap.packet.DNSPacket;
import nl.sidnlabs.pcap.packet.Datagram;
import nl.sidnlabs.pcap.packet.DatagramPayload;
import nl.sidnlabs.pcap.packet.ICMPPacket;
import nl.sidnlabs.pcap.packet.Packet;
import nl.sidnlabs.pcap.packet.PacketFactory;
import nl.sidnlabs.pcap.packet.TCPFlow;
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

  private PacketReader tcpReader;
  private PacketReader udpReader;
  private ICMPDecoder icmpDecoder;


  public IPDecoder(PacketReader tcpReader, PacketReader udpReader, ICMPDecoder icmpDecoder) {
    this.tcpReader = tcpReader;
    this.udpReader = udpReader;
    this.icmpDecoder = icmpDecoder;
  }


  public Packet decode(byte[] packetData, int ipStart) {
    Packet p = createPacket(packetData, ipStart);
    return decode(p, packetData, ipStart);
  }

  public Packet decode(Packet packet, byte[] packetData, int ipStart) {

    if (ipStart == -1)
      return Packet.NULL;

    int ipProtocolHeaderVersion = IPv4Util.getInternetProtocolHeaderVersion(packetData, ipStart);
    packet.setIpVersion(ipProtocolHeaderVersion);

    int totalLength = 0;
    if (ipProtocolHeaderVersion == IP_PROTOCOL_VERSION_4) {
      int ipHeaderLen = IPv4Util.getInternetProtocolHeaderLength(packetData, ipStart);
      packet.setIpHeaderLen(ipHeaderLen);

      buildInternetProtocolV4Packet(packet, packetData, ipStart);
      totalLength = PcapReaderUtil.convertShort(packetData, ipStart + IP_TOTAL_LEN_OFFSET);
      decodeV4Fragmented(packet, ipStart, packetData);
    } else {
      int ipHeaderLen = IPv6Util.getInternetProtocolHeaderLength(packetData, ipStart);
      packet.setIpHeaderLen(ipHeaderLen);

      buildInternetProtocolV6Packet(packet, packetData, ipStart);
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
    int padding = packetData.length - (totalLength + ipStart);
    if (padding > 0) {
      /*
       * make sure there is no ethernet padding present. see: https://wiki.wireshark.org/Ethernet
       * padding present, copy all data except the padding, to avoid problems decoding tcp/udp/dns
       */
      packetData = Arrays.copyOfRange(packetData, ipStart, packetData.length - padding);
    }

    byte[] reassembledData = reassemble(packet, packetData, ipStart);
    // if reassembledData is empty then the IP packet is fragmented and is not the final fragment
    if (reassembledData.length == 0) {
      return Packet.NULL;
    }

    return handlePayload(packet, packetData, ipStart);
  }


  public Packet createPacket(byte[] packetData, int ipStart) {
    int ipProtocolHeaderVersion = IPv4Util.getInternetProtocolHeaderVersion(packetData, ipStart);
    int protocol = -1;

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

  private Packet handlePayload(Packet packet, byte[] packetData, int offset) {

    if ((PacketFactory.PROTOCOL_ICMP_V4 == packet.getProtocol())
        || (PacketFactory.PROTOCOL_ICMP_V6 == packet.getProtocol())) {
      // found icmp protocol
      ICMPPacket icmpPacket = (ICMPPacket) packet;
      icmpDecoder.reassemble(icmpPacket, packetData, offset);
      // do not process icmp packet further, because the dns packet might be corrupt (only 8 bytes
      // in icmp packet)
      return icmpPacket;
    }

    Packet dnsPacket = null;

    if (PacketFactory.PROTOCOL_TCP == packet.getProtocol()) {
      // found TCP protocol
      dnsPacket = tcpReader.reassemble(packet, packetData, offset);
    } else if (PacketFactory.PROTOCOL_UDP == packet.getProtocol()) {
      // found UDP protocol
      dnsPacket = udpReader.reassemble(packet, packetData, offset);
    }

    if ((dnsPacket == null || dnsPacket == Packet.NULL)
        || (dnsPacket instanceof DNSPacket && ((DNSPacket) dnsPacket).getMessageCount() == 0)) {
      // no dns message(s) found
      return Packet.NULL;
    }

    return dnsPacket;
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

    int flags = packetData[ipStart + IP_FLAGS] & 0xE0;

    if ((flags & 0x20) != 0 || fragmentOffset != 0) {
      packet.setFragmented(true);
      packet.setLastFragment(((flags & 0x20) == 0 && fragmentOffset != 0));
    } else {
      packet.setFragmented(false);
    }
  }


  private void buildInternetProtocolV4Packet(Packet packet, byte[] packetData, int ipStart) {
    packet.setTtl(IPv4Util.decodeTTL(packetData, ipStart));
    packet.setSrc(IPv4Util.decodeSrc(packetData, ipStart));
    packet.setDst(IPv4Util.decodeDst(packetData, ipStart));
    packet.setIpId(IPv4Util.decodeId(packetData, ipStart));
  }

  private void buildInternetProtocolV6Packet(Packet packet, byte[] packetData, int ipStart) {
    packet.setTtl(IPv6Util.decodeTTL(packetData, ipStart));
    packet.setSrc(IPv6Util.decodeSrc(packetData, ipStart));
    packet.setDst(IPv6Util.decodeDst(packetData, ipStart));
    packet.setIpId(IPv6Util.decodeId(packetData, ipStart));
  }


  public byte[] reassemble(Packet packet, byte[] packetData, int ipStart) {
    // reassemble IP fragments
    byte[] reassmbledPacketData = packetData;

    if (packet.isFragmented()) {

      Datagram datagram = packet.getDatagram();
      byte[] fragmentPacketData = Arrays
          .copyOfRange(packetData, ipStart + packet.getIpHeaderLen(),
              ipStart + packet.getTotalLength());
      DatagramPayload payload = new DatagramPayload(packet.getFragOffset(), fragmentPacketData);
      datagrams.put(datagram, payload);

      if (packet.isLastFragment()) {
        Collection<DatagramPayload> datagramPayloads = datagrams.removeAll(datagram);
        if (datagramPayloads != null && !datagramPayloads.isEmpty()) {
          reassmbledPacketData =
              Arrays.copyOfRange(packetData, 0, ipStart + packet.getIpHeaderLen()); // Start
                                                                                    // re-fragmented
                                                                                    // packet with
                                                                                    // IP header
                                                                                    // from current
                                                                                    // packet

          int reassembledFragments = 0;
          DatagramPayload prev = null;
          for (DatagramPayload datagramPayload : datagramPayloads) {
            if (prev == null && datagramPayload.getOffset() != 0) {
              if (log.isDebugEnabled()) {
                log
                    .debug(
                        "Datagram chain not starting at 0. Probably received packets out-of-order. Can't reassemble this packet.");
              }
              // do not even try to reasemble the data, probably corrupt packets.
              return new byte[0];
            }
            if (prev != null && !datagramPayload.linked(prev)) {
              if (log.isDebugEnabled()) {
                log
                    .debug("Broken datagram chain between " + datagramPayload + " and " + prev
                        + ". Can't reassemble this packet.");
              }
              // do not even try to reasemble the data, probably corrupt packets.
              return new byte[0];
            }
            reassmbledPacketData = Bytes.concat(reassmbledPacketData, datagramPayload.getPayload());
            reassembledFragments++;
            prev = datagramPayload;
          }
          if (reassembledFragments == datagramPayloads.size()) {
            packet.setReassembledFragments(reassembledFragments);
          }
        }

      } else {
        // need last IP fragment before continu to tcp/udp reassembly
        reassmbledPacketData = new byte[0];
      }
    }
    return reassmbledPacketData;
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
   * @param tcpFlowCacheTimeout timeout for tcp flows
   * @param fragmentedIPcacheTimeout timeout for IP fragments
   */
  public void clearCache(int tcpFlowCacheTimeout, int fragmentedIPcacheTimeout) {
    // clear tcp flows with expired packets
    List<TCPFlow> expiredList = new ArrayList<>();
    long now = System.currentTimeMillis();
    Multimap<TCPFlow, SequencePayload> flows = ((TCPDecoder) tcpReader).getFlows();
    for (TCPFlow flow : flows.keySet()) {
      Collection<SequencePayload> payloads = flows.get(flow);
      for (SequencePayload sequencePayload : payloads) {
        if ((sequencePayload.getTime() + tcpFlowCacheTimeout) <= now) {
          expiredList.add(flow);
          break;
        }
      }
    }

    // check IP datagrams
    List<Datagram> dgExpiredList = new ArrayList<>();

    for (Datagram dg : getDatagrams().keySet()) {
      if ((dg.getTime() + fragmentedIPcacheTimeout) <= now) {
        dgExpiredList.add(dg);
      }
    }

    log.info("------------- Cache purge stats --------------");
    log.info("TCP flow cache size: " + flows.size());
    log.info("IP datagram cache size: " + getDatagrams().size());
    log.info("Expired (to be removed) TCP flows: " + expiredList.size());
    log.info("Expired (to be removed) IP datagrams: " + dgExpiredList.size());
    log.info("----------------------------------------------------");

    // remove flows with expired packets
    for (TCPFlow tcpFlow : expiredList) {
      flows.removeAll(tcpFlow);
    }

    for (Datagram dg : dgExpiredList) {
      getDatagrams().removeAll(dg);
    }

  }
}
