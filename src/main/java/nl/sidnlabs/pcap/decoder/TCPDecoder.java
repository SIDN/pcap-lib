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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import nl.sidnlabs.pcap.PcapReader;
import nl.sidnlabs.pcap.PcapReaderUtil;
import nl.sidnlabs.pcap.SequencePayload;
import nl.sidnlabs.pcap.packet.DNSPacket;
import nl.sidnlabs.pcap.packet.Packet;
import nl.sidnlabs.pcap.packet.TCPFlow;
import nl.sidnlabs.pcap.packet.TcpHandshake;
import nl.sidnlabs.pcap.packet.TcpHandshake.HANDSHAKE_STATE;

@Data
@Log4j2
public class TCPDecoder implements PacketReader {

  public static final int PROTOCOL_HEADER_TCP_SEQ_OFFSET = 4;
  public static final int PROTOCOL_HEADER_TCP_ACK_OFFSET = 8;
  public static final int TCP_HEADER_DATA_OFFSET = 12;
  public static final int PROTOCOL_HEADER_WINDOW_SIZE_OFFSET = 14;

  public static final int TCP_DNS_LENGTH_PREFIX = 2;

  private DNSDecoder dnsDecoder = new DNSDecoder();

  protected Multimap<TCPFlow, SequencePayload> flows = TreeMultimap.create();
  protected Multimap<TCPFlow, Long> flowseq = TreeMultimap.create();

  protected Map<TCPFlow, TcpHandshake> handshakes = new HashMap<>();

  private int tcpPrefixError = 0;


  public byte[] decode(Packet packet, byte[] packetData, int offset) {
    packet
        .setSrcPort(PcapReaderUtil
            .convertShort(packetData,
                offset + packet.getIpHeaderLen() + PcapReader.PROTOCOL_HEADER_SRC_PORT_OFFSET));
    packet
        .setDstPort(PcapReaderUtil
            .convertShort(packetData,
                offset + packet.getIpHeaderLen() + PcapReader.PROTOCOL_HEADER_DST_PORT_OFFSET));

    int tcpOrUdpHeaderSize = getTcpHeaderLength(packetData, offset + packet.getIpHeaderLen());
    if (tcpOrUdpHeaderSize == -1) {
      return new byte[0];
    }
    packet.setTcpHeaderLen(tcpOrUdpHeaderSize);

    // Store the sequence and acknowledgement numbers --M
    packet
        .setTcpSeq(PcapReaderUtil
            .convertUnsignedInt(packetData,
                offset + packet.getIpHeaderLen() + PROTOCOL_HEADER_TCP_SEQ_OFFSET));
    packet
        .setTcpAck(PcapReaderUtil
            .convertUnsignedInt(packetData,
                offset + packet.getIpHeaderLen() + PROTOCOL_HEADER_TCP_ACK_OFFSET));
    // Flags stretch two bytes starting at the TCP header offset
    int flags = PcapReaderUtil
        .convertShort(
            new byte[] {packetData[offset + packet.getIpHeaderLen() + TCP_HEADER_DATA_OFFSET],
                packetData[offset + packet.getIpHeaderLen() + TCP_HEADER_DATA_OFFSET + 1]})
        & 0x1FF; // Filter first 7 bits. First 4 are the data offset and the other 3 reserved for
                 // future use.

    packet.setTcpFlagNs((flags & 0x100) == 0 ? false : true);
    packet.setTcpFlagCwr((flags & 0x80) == 0 ? false : true);
    packet.setTcpFlagEce((flags & 0x40) == 0 ? false : true);
    packet.setTcpFlagUrg((flags & 0x20) == 0 ? false : true);
    packet.setTcpFlagAck((flags & 0x10) == 0 ? false : true);
    packet.setTcpFlagPsh((flags & 0x8) == 0 ? false : true);
    packet.setTcpFlagRst((flags & 0x4) == 0 ? false : true);
    packet.setTcpFlagSyn((flags & 0x2) == 0 ? false : true);
    packet.setTcpFlagFin((flags & 0x1) == 0 ? false : true);

    // WINDOW size
    packet
        .setTcpWindowSize(PcapReaderUtil
            .convertShort(packetData,
                offset + packet.getIpHeaderLen() + PROTOCOL_HEADER_WINDOW_SIZE_OFFSET));

    int payloadDataStart = offset + packet.getIpHeaderLen() + tcpOrUdpHeaderSize;
    int payloadLength = packetData.length - payloadDataStart;

    byte[] data = PcapReaderUtil.readPayload(packetData, payloadDataStart, payloadLength);

    packet.setPayloadLength(payloadLength);
    // total length of packet
    packet.setUdpLength(packetData.length);
    return data;
  }

  /**
   * decode the packetdata
   * 
   * @param packet
   * @param ipHeaderLen
   * @param totalLength
   * @param ipStart
   * @param packetData
   * @return payload bytes or null if not a valid packet
   */
  public Packet reassemble(Packet packet, byte[] packetData, int offset) {
    byte[] packetPayload = decode(packet, packetData, offset);

    if (packet.getSrcPort() != PcapReader.DNS_PORT && packet.getDstPort() != PcapReader.DNS_PORT) {
      // not a dns packet, ignore
      return Packet.NULL;
    }

    if (packet.isTcpFlagRst()) {
      // reset flag is set, connection should be reset, clear all state
      TCPFlow flow = packet.getFlow();
      handshakes.remove(flow);
      flows.removeAll(flow);
      return Packet.NULL;
    }

    // get the flow details for this packet
    TCPFlow flow = packet.getFlow();

    if (checkForHandshake(packet, flow)) {
      // packet is part of handshake, do not process payload
      return Packet.NULL;
    }

    // normal post-handshake processing starts here
    // save all tcp payload data until we get a signal to push the data up the stack
    if (packetPayload.length > 0) {
      SequencePayload sequencePayload =
          new SequencePayload(packet.getTcpSeq(), packetPayload, System.currentTimeMillis());
      flows.put(flow, sequencePayload);
    }

    if (packet.isTcpFlagFin() || packet.isTcpFlagPsh()) {
      // received signal to push the data received for this flow up the stack.
      Collection<SequencePayload> fragments = flows.removeAll(flow);
      if (fragments != null && !fragments.isEmpty()) {
        packet.setReassembledTCPFragments(fragments.size());
        SequencePayload prev = null;

        // calc toal size of payload
        int totalSize = 0;
        for (SequencePayload seqPayload : fragments) {
          totalSize += seqPayload.getPayload().length;
        }
        packetPayload = new byte[totalSize];
        int destPos = 0;

        // copy all the payload bytes
        for (SequencePayload seqPayload : fragments) {
          if (prev != null && !seqPayload.linked(prev)) {
            log
                .warn("Packet src: " + packet.getSrc() + " dst: " + packet.getDst()
                    + " has Broken sequence chain between " + seqPayload + " and " + prev
                    + ". Returning empty payload.");
            packetPayload = new byte[0];
            tcpPrefixError++;
            // got chain linkage error, ignore all data, return nothing. (these bytes cannot be
            // decoded)
            break;
          }

          // copy all tcp data segments into a single array, packetPayload
          System
              .arraycopy(seqPayload.getPayload(), 0, packetPayload, destPos,
                  seqPayload.getPayload().length);
          destPos += seqPayload.getPayload().length;

          prev = seqPayload;
        }
        // return the data for processing up the stack
        // also add the tcph andshake (if found) to the first packet
        TcpHandshake handshake = handshakes.remove(flow);
        if (handshake != null && HANDSHAKE_STATE.ACK_RECV == handshake.getState()) {
          // add handshake to the first packet after the handshake was completed, must be in state
          // HANDSHAKE_STATE.ACK_RECV
          packet.setTcpHandshake(handshake);
        }
        return handleDNS(packet, packetPayload);
      }
    }

    // no fin or push flag signal detected, do not return any bytes yet to upper protocol decoder.
    return Packet.NULL;
  }

  /**
   * 
   * @param packet
   * @param flow
   * @return true when handshake packet is detected and payload processing should not continue
   */
  private boolean checkForHandshake(Packet packet, TCPFlow flow) {
    if (packet.isTcpFlagSyn() && !packet.isTcpFlagAck()) {
      // this is a client syn for a new TCP connection, create handshake and return
      TcpHandshake handshake = new TcpHandshake(packet.getTcpSeq());
      handshake.setSynTs(packet.getTsMilli());
      handshakes.put(flow, handshake);
      return true;
    } else if (packet.isTcpFlagSyn() && packet.isTcpFlagAck()) {
      // this is a server syn/ack, lookup the flow by reversing the src/dst
      TCPFlow reverseFlow = packet.getReverseFlow();
      TcpHandshake handshake = handshakes.get(reverseFlow);
      // handshake and server sequence number +1 must match
      if (handshake != null && handshake.getClientSynSeq() == packet.getTcpAck() - 1) {
        // got syn/ack for the handshake
        if (HANDSHAKE_STATE.SYN_RECV == handshake.getState()) {
          handshake.setState(HANDSHAKE_STATE.SYN_ACK_SENT);
          handshake.setServerAckSeq(packet.getTcpAck());
          handshake.setServerSynSeq(packet.getTcpSeq());
        } else {
          // incorrect state, maybe retransmission, ignore this handshake.
          // retransmission in the handshake can give incorrent results
          // for rtt measurements
          handshakes.remove(reverseFlow);
        }
      } else if (log.isDebugEnabled()) {
        log.debug("Cannot find handshake for SYN/ACK, maybe a retry?");
      }
      return true;
    } else if (packet.isTcpFlagAck()) {
      // this could be the final client ack for the handshake
      TcpHandshake handshake = handshakes.get(flow);
      if (handshake != null && HANDSHAKE_STATE.SYN_ACK_SENT == handshake.getState()
          && packet.getTcpAck() - 1 == handshake.getServerSynSeq()) {
        // state and seq number match, got final ack for the handshake, connection complete
        handshake.setAckTs(packet.getTsMilli());
        handshake.setState(HANDSHAKE_STATE.ACK_RECV);
        handshake.setClientAckSeq(packet.getTcpSeq());
        // check for PSH flag
        if (!packet.isTcpFlagPsh()) {
          // if PUSH flag not set then no data in this packet, just an ack.
          return true;
        }
      }
    }

    return false;
  }

  private int getTcpHeaderLength(byte[] packet, int tcpStart) {
    int dataOffset = tcpStart + TCP_HEADER_DATA_OFFSET;
    if (dataOffset < packet.length) {
      return ((packet[dataOffset] >> 4) & 0xF) * 4;
    }
    // invalid header
    return -1;
  }

  private Packet handleDNS(Packet packet, byte[] payload) {
    /*
     * TCP flow may contain multiple dns messages break the TCP flow into the individual dns msg
     * blocks, every dns msg has a 2 byte msg prefix need at least the 2 byte len prefix to start.
     */
    int payloadIndex = 0;
    while ((payload.length > TCPDecoder.TCP_DNS_LENGTH_PREFIX) && (payloadIndex < payload.length)) {
      byte[] lenBytes = new byte[2];
      System.arraycopy(payload, payloadIndex, lenBytes, 0, 2);
      int msgLen = PcapReaderUtil.convertShort(lenBytes);
      // add the 2byte msg len
      payloadIndex += 2;
      if ((payloadIndex + msgLen) <= payload.length) {
        byte[] msgBytes = new byte[msgLen];
        System.arraycopy(payload, payloadIndex, msgBytes, 0, msgLen);
        createDnsPacket(packet, msgBytes);
        // add the msg len to the index
        payloadIndex += msgLen;
      } else {
        // invalid msg len
        if (log.isDebugEnabled()) {
          log
              .debug("Invalid TCP payload length, msgLen= " + msgLen + " tcpOrUdpPayload.length= "
                  + payload.length + " ack=" + packet.isTcpFlagAck());
        }
        break;
      }
    }
    if (log.isDebugEnabled() && ((DNSPacket) packet).getMessageCount() > 1) {
      log.debug("multiple msg in TCP stream");
    }

    return packet;
  }

  private Packet createDnsPacket(Packet packet, byte[] packetPayload) {

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

}
