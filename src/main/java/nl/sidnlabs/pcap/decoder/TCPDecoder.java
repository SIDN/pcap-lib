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
import nl.sidnlabs.pcap.decoder.TcpHandshake.HANDSHAKE_STATE;
import nl.sidnlabs.pcap.packet.Packet;
import nl.sidnlabs.pcap.packet.TCPFlow;

@Data
@Log4j2
public class TCPDecoder {


  public static final int PROTOCOL_HEADER_TCP_SEQ_OFFSET = 4;
  public static final int PROTOCOL_HEADER_TCP_ACK_OFFSET = 8;
  public static final int TCP_HEADER_DATA_OFFSET = 12;
  public static final int PROTOCOL_HEADER_WINDOW_SIZE_OFFSET = 14;

  public static final byte[] EMPTY_PAYLOAD = new byte[0];

  protected Multimap<TCPFlow, SequencePayload> flows = TreeMultimap.create();
  protected Multimap<TCPFlow, Long> flowseq = TreeMultimap.create();

  protected Map<TCPFlow, TcpHandshake> handshakes = new HashMap<>();

  private int tcpPrefixError = 0;


  public byte[] decode(Packet packet, byte[] packetData, int ipStart, int ipHeaderLen,
      int totalLength) {
    packet
        .setSrcPort(PcapReaderUtil
            .convertShort(packetData,
                ipStart + ipHeaderLen + PcapReader.PROTOCOL_HEADER_SRC_PORT_OFFSET));
    packet
        .setDstPort(PcapReaderUtil
            .convertShort(packetData,
                ipStart + ipHeaderLen + PcapReader.PROTOCOL_HEADER_DST_PORT_OFFSET));

    int tcpOrUdpHeaderSize = getTcpHeaderLength(packetData, ipStart + ipHeaderLen);
    if (tcpOrUdpHeaderSize == -1) {
      return new byte[0];
    }
    packet.setTcpHeaderLen(tcpOrUdpHeaderSize);

    // Store the sequence and acknowledgement numbers --M
    packet
        .setTcpSeq(PcapReaderUtil
            .convertUnsignedInt(packetData,
                ipStart + ipHeaderLen + PROTOCOL_HEADER_TCP_SEQ_OFFSET));
    packet
        .setTcpAck(PcapReaderUtil
            .convertUnsignedInt(packetData,
                ipStart + ipHeaderLen + PROTOCOL_HEADER_TCP_ACK_OFFSET));
    // Flags stretch two bytes starting at the TCP header offset
    int flags = PcapReaderUtil
        .convertShort(new byte[] {packetData[ipStart + ipHeaderLen + TCP_HEADER_DATA_OFFSET],
            packetData[ipStart + ipHeaderLen + TCP_HEADER_DATA_OFFSET + 1]})
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
            .convertShort(packetData, ipStart + ipHeaderLen + PROTOCOL_HEADER_WINDOW_SIZE_OFFSET));

    int payloadDataStart = ipStart + ipHeaderLen + tcpOrUdpHeaderSize;
    int payloadLength = totalLength - ipHeaderLen - tcpOrUdpHeaderSize;
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
  public byte[] reassemble(Packet packet, int ipHeaderLen, int totalLength, int ipStart,
      byte[] packetData) {
    byte[] packetPayload = decode(packet, packetData, ipStart, ipHeaderLen, totalLength);

    if (packet.getSrcPort() != PcapReader.DNS_PORT && packet.getDstPort() != PcapReader.DNS_PORT) {
      // not a dns packet, ignore
      return EMPTY_PAYLOAD;
    }
    // get the flow details for this packet
    TCPFlow flow = packet.getFlow();
    if (packet.isTcpFlagSyn() && !(packet.isTcpFlagSyn() && packet.isTcpFlagAck())) {
      // this is a new TCP connection, create handshake and return
      TcpHandshake handshake = new TcpHandshake();
      handshake.setSynTs(packet.getTsMilli());
      handshakes.put(flow, handshake);
      return EMPTY_PAYLOAD;
    }

    if (packet.isTcpFlagSyn() && packet.isTcpFlagAck()) {
      TCPFlow reverseFlow = packet.getReverseFlow();
      TcpHandshake handshake = handshakes.get(reverseFlow);
      if (handshake != null) {
        // got syn/ack for the handshake
        if (HANDSHAKE_STATE.SYN_RECV == handshake.getState()) {
          handshake.setState(HANDSHAKE_STATE.SYN_ACK_SENT);
        } else {
          // illegal state
          log
              .error("Found TCP handshake but state is {} and should be {}", handshake.getState(),
                  HANDSHAKE_STATE.SYN_RECV);
          handshakes.remove(reverseFlow);
        }
      } else {
        log.error("Cannot find handshake for SYN/ACK");
      }
      return EMPTY_PAYLOAD;
    }

    if (packet.isTcpFlagAck()) {
      TcpHandshake handshake = handshakes.get(flow);
      if (handshake != null && HANDSHAKE_STATE.SYN_ACK_SENT == handshake.getState()) {
        // got final ack for the handshake, connection complete
        handshake.setAckTs(packet.getTsMilli());
        handshake.setState(HANDSHAKE_STATE.ACK_RECV);
        return EMPTY_PAYLOAD;
      }
    }

    TcpHandshake handshake = handshakes.remove(flow);
    if (handshake != null && HANDSHAKE_STATE.ACK_RECV == handshake.getState()) {
      // add handshake to the first packet after the handshake was completed
      packet.setTcpHandshake(handshake);
    }

    // keep all tcp data until we get a signal to push the data up the stack
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
                .warn("Broken sequence chain between " + seqPayload + " and " + prev
                    + ". Returning empty payload.");
            packetPayload = EMPTY_PAYLOAD;
            tcpPrefixError++;
            // got chain linkage error, ignore all flow data return nothing. (these bytes will be
            // ubnparseble)
            break;
          }
          System
              .arraycopy(seqPayload.getPayload(), 0, packetPayload, destPos,
                  seqPayload.getPayload().length);
          destPos += seqPayload.getPayload().length;

          prev = seqPayload;
        }
        // return the combined payload data for processing up the stack
        return packetPayload;
      }
    }

    // no fin or push flag signal detected, do not return any bytes yet to upper protocol decoder.
    return EMPTY_PAYLOAD;
  }

  private int getTcpHeaderLength(byte[] packet, int tcpStart) {
    int dataOffset = tcpStart + TCP_HEADER_DATA_OFFSET;
    if (dataOffset < packet.length) {
      return ((packet[dataOffset] >> 4) & 0xF) * 4;
    }
    // invalid header
    return -1;
  }
}
