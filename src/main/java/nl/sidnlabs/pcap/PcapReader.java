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
package nl.sidnlabs.pcap;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.apache.commons.codec.binary.Hex;
import com.google.common.collect.Multimap;
import lombok.extern.log4j.Log4j2;
import nl.sidnlabs.pcap.decoder.ICMPDecoder;
import nl.sidnlabs.pcap.decoder.IPDecoder;
import nl.sidnlabs.pcap.decoder.TCPDecoder;
import nl.sidnlabs.pcap.decoder.UDPDecoder;
import nl.sidnlabs.pcap.packet.Datagram;
import nl.sidnlabs.pcap.packet.DatagramPayload;
import nl.sidnlabs.pcap.packet.Packet;
import nl.sidnlabs.pcap.packet.TCPFlow;

/**
 * Read all data from a pcap file and decode all the packets
 *
 */
@Log4j2
public class PcapReader {

  // needs no explanation
  public static final int DNS_PORT = 53;
  public static final long MAGIC_NUMBER = 0xA1B2C3D4;
  public static final int HEADER_SIZE = 24;
  public static final int PCAP_HEADER_LINKTYPE_OFFSET = 20;
  public static final int PACKET_HEADER_SIZE = 16;
  public static final int TIMESTAMP_OFFSET = 0;
  public static final int TIMESTAMP_MICROS_OFFSET = 4;
  public static final int CAP_LEN_OFFSET = 8;
  public static final int ETHERNET_HEADER_SIZE = 14;
  public static final int ETHERNET_TYPE_OFFSET = 12;
  public static final int ETHERNET_TYPE_IP = 0x800;
  public static final int ETHERNET_TYPE_IPV6 = 0x86dd;
  public static final int ETHERNET_TYPE_8021Q = 0x8100;
  public static final int SLL_HEADER_BASE_SIZE = 10; // SLL stands for Linux cooked-mode capture
  public static final int SLL_ADDRESS_LENGTH_OFFSET = 4; // relative to SLL header
  public static final int PROTOCOL_HEADER_SRC_PORT_OFFSET = 0;
  public static final int PROTOCOL_HEADER_DST_PORT_OFFSET = 2;

  public static final int PROTOCOL_FRAGMENTED = -1;

  private DataInputStream is;
  private LinkType linkType;

  // To read reversed-endian PCAPs; the header is the only part that switches
  private boolean reverseHeaderByteOrder = false;

  // metrics
  private int packetCounter;

  private TCPDecoder tcpDecoder = new TCPDecoder();
  private IPDecoder ipDecoder = new IPDecoder(tcpDecoder, new UDPDecoder(), new ICMPDecoder());

  public PcapReader(DataInputStream is) throws IOException {
    log.info("Create new PCAP reader");
    this.is = is;

    byte[] pcapHeader = new byte[HEADER_SIZE];
    if (!readBytes(pcapHeader)) {
      //
      // This special check for EOF is because we don't want
      // PcapReader to barf on an empty file. This is the only
      // place we check caughtEOF.
      //
      throw new IOException("Couldn't read PCAP header");
    }

    if (!validateMagicNumber(pcapHeader))
      throw new IOException("Not a PCAP file (Couldn't find magic number)");

    long linkTypeVal =
        PcapReaderUtil.convertInt(pcapHeader, PCAP_HEADER_LINKTYPE_OFFSET, reverseHeaderByteOrder);
    if ((linkType = getLinkType(linkTypeVal)) == null)
      throw new IOException("Unsupported link type: " + linkTypeVal);
  }

  public Stream<Packet> stream() {
    Iterable<Packet> valueIterable = PacketIterator::new;
    return StreamSupport.stream(valueIterable.spliterator(), false);
  }


  /**
   * Clear expired cache entries in order to avoid memory problems
   * 
   * @param tcpFlowCacheTimeout timeout for tcp flows
   * @param fragmentedIPcacheTimeout timeout for IP fragments
   */
  public void clearCache(int tcpFlowCacheTimeout, int fragmentedIPcacheTimeout) {
    ipDecoder.clearCache(tcpFlowCacheTimeout, fragmentedIPcacheTimeout);
  }

  public void close() {
    try {
      is.close();
    } catch (IOException e) {
      log.error("Error closing PCAP data inputstream", e);
    }
  }

  private Packet nextPacket() {
    byte[] pcapPacketHeader = new byte[PACKET_HEADER_SIZE];
    if (!readBytes(pcapPacketHeader)) {
      // no more data left
      return null;
    }

    long packetSize =
        PcapReaderUtil.convertInt(pcapPacketHeader, CAP_LEN_OFFSET, reverseHeaderByteOrder);
    byte[] packetData = new byte[(int) packetSize];

    if (!readBytes(packetData))
      return Packet.NULL;

    // find the start pos of the ip packet in the pcap frame
    int ipStart = findIPStart(packetData);

    if (ipStart == -1) {
      if (log.isDebugEnabled()) {
        log.debug("Invalid IP packet: {}", Hex.encodeHexString(packetData));
      }
      return Packet.NULL;
    }

    // first create the packet so the timestamps can be added to the packet.
    // these timestamps are needed by the protocol decoders.
    Packet packet = ipDecoder.createPacket(packetData, ipStart);

    // the pcap header for ervy packet contains a timestamp with the capture datetime of the packet
    long packetTimestampSecs =
        PcapReaderUtil.convertInt(pcapPacketHeader, TIMESTAMP_OFFSET, reverseHeaderByteOrder);
    packet.setTsSec(packetTimestampSecs);
    long packetTimestampMicros = PcapReaderUtil
        .convertInt(pcapPacketHeader, TIMESTAMP_MICROS_OFFSET, reverseHeaderByteOrder);
    packet.setTsMicro(packetTimestampMicros);

    // calc the timestamp in milliseconds = seconds + micros combined
    packet.setTsMilli((packetTimestampSecs * 1000) + Math.round(packetTimestampMicros / 1000f));

    // decode the packet bytes
    // the "packet" param is handed to the decode method as a parameter and
    // will be updated with decoded values, DO NOT use this param anymore
    // after calling IpDecoder::decode use the method result
    Packet decodedPacket = ipDecoder.decode(packet, packetData, ipStart);

    packetCounter++;
    return decodedPacket;
  }

  protected boolean validateMagicNumber(byte[] pcapHeader) {
    if (PcapReaderUtil.convertInt(pcapHeader) == MAGIC_NUMBER) {
      return true;
    } else if (PcapReaderUtil.convertInt(pcapHeader, true) == MAGIC_NUMBER) {
      reverseHeaderByteOrder = true;
      return true;
    } else {
      return false;
    }
  }

  protected enum LinkType {
    NULL, EN10MB, RAW, LOOP, LINUX_SLL
  }

  protected LinkType getLinkType(long linkTypeVal) {
    switch ((int) linkTypeVal) {
      case 0:
        return LinkType.NULL;
      case 1:
        return LinkType.EN10MB;
      case 101:
        return LinkType.RAW;
      case 108:
        return LinkType.LOOP;
      case 113:
        return LinkType.LINUX_SLL;
      default:
        return null;
    }
  }

  protected int findIPStart(byte[] packet) {
    int start = -1;
    switch (linkType) {
      case NULL:
        return 4;
      case EN10MB:
        start = ETHERNET_HEADER_SIZE;
        int etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET);
        if (etherType == ETHERNET_TYPE_8021Q) {
          etherType = PcapReaderUtil.convertShort(packet, ETHERNET_TYPE_OFFSET + 4);
          start += 4;
        }
        if (etherType == ETHERNET_TYPE_IP || etherType == ETHERNET_TYPE_IPV6)
          return start;
        break;
      case RAW:
        return 0;
      case LOOP:
        return 4;
      case LINUX_SLL:
        start = SLL_HEADER_BASE_SIZE;
        int sllAddressLength = PcapReaderUtil.convertShort(packet, SLL_ADDRESS_LENGTH_OFFSET);
        start += sllAddressLength;
        return start;
    }
    return -1;
  }



  protected boolean readBytes(byte[] buf) {
    try {
      is.readFully(buf);
      return true;
    } catch (IOException e) {
      log.error("Error while reading " + buf.length + " bytes from buffer");
      return false;
    }
  }

  public Map<TCPFlow, FlowData> getFlows() {
    return tcpDecoder.getFlows();
  }

  public void setFlows(Map<TCPFlow, FlowData> flows) {
    tcpDecoder.setFlows(flows);
  }

  private class PacketIterator implements Iterator<Packet> {
    private Packet next;

    private void fetchNext() {
      if (next == null) {
        // skip fragmented packets until they are assembled
        do {
          try {
            next = nextPacket();
          } catch (Exception e) {
            log.error("PCAP decode error: ", e);
            next = Packet.NULL;
          }
        } while (next == Packet.NULL);
      }
    }

    @Override
    public boolean hasNext() {
      // fetchNext will keep result in "next" var so that when next() is
      // called the data does not have to be parsed a 2nd time
      fetchNext();
      if (next != null)
        return true;

      // no more data left
      int remainingFlows = tcpDecoder.getFlows().size() + ipDecoder.getDatagrams().size();
      if (remainingFlows > 0) {
        log.warn("Still " + remainingFlows + " flows queued. Missing packets to finish assembly?");
        log.warn("Packets processed: " + packetCounter);
      }

      return false;
    }

    @Override
    public Packet next() {
      fetchNext();

      if (next == null) {
        throw new NoSuchElementException("No more packets to decode");
      }
      try {
        return next;
      } finally {
        // make sure to set next to null so the next packet is read from the stream
        next = null;
      }
    }

    @Override
    public void remove() {
      // Not supported
    }
  }

  public Multimap<Datagram, DatagramPayload> getDatagrams() {
    return ipDecoder.getDatagrams();
  }

  public void setDatagrams(Multimap<Datagram, DatagramPayload> map) {
    ipDecoder.setDatagrams(map);
  }

}
