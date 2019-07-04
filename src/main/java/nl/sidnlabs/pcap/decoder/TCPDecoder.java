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

  private static final int PROTOCOL_HEADER_TCP_SEQ_OFFSET = 4;
  private static final int PROTOCOL_HEADER_TCP_ACK_OFFSET = 8;
  private static final int TCP_HEADER_DATA_OFFSET = 12;
  private static final int PROTOCOL_HEADER_WINDOW_SIZE_OFFSET = 14;

  private static final int TCP_DNS_LENGTH_PREFIX = 2;

  private DNSDecoder dnsDecoder = new DNSDecoder();

  private Multimap<TCPFlow, SequencePayload> flows = TreeMultimap.create();
  private Multimap<TCPFlow, Long> flowseq = TreeMultimap.create();
  private Map<TCPFlow, TcpHandshake> handshakes = new HashMap<>();
  // keep reassembled packets until a ack is received and the ack time can be added to the packet
  private Map<TCPFlow, Packet> reassembledPackets = new HashMap<>();

  private int reqPacketCounter = 0;
  private int rspPacketCounter = 0;


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
    packet.setLen(packetData.length);

    return data;
  }

  /**
   * decode the packetdata
   * 
   * @param packet network packet
   * @param packetData data to assemble
   * @param offset start of data in packetData
   * @return reassembled packet of NULL packet
   */
  public Packet reassemble(Packet packet, byte[] packetData, int offset) {
    byte[] packetPayload = decode(packet, packetData, offset);

    if (packet.getSrcPort() != PcapReader.DNS_PORT && packet.getDstPort() != PcapReader.DNS_PORT) {
      // not a dns packet, ignore
      return Packet.NULL;
    }

    if (packet.isTcpFlagRst()) {
      // reset flag is set, connection should be reset, clear all state
      if (log.isDebugEnabled()) {
        log.debug("Connection RESET for: {}", packet);
      }
      TCPFlow flow = packet.getFlow();
      handshakes.remove(flow);
      flows.removeAll(flow);
      reassembledPackets.remove(flow);
      return Packet.NULL;
    }

    // get the flow details for this packet
    TCPFlow flow = packet.getFlow();
    boolean isServer = packet.getSrcPort() == PcapReader.DNS_PORT;
    boolean hasPayload = packetPayload.length > 0;

    if (handshake(packet, isServer)) {
      // packet is part of handshake, do not continue because
      // there is no payload data
      return Packet.NULL;
    }

    // normal post-handshake processing starts here
    if (isServer && packet.isTcpFlagAck() && hasPayload) {
      Packet reassembledPacket = reassembledPackets.get(packet.getReverseFlow());
      if (reassembledPacket != null && reassembledPacket.getTcpSeq() == packet.getTcpSeq()) {
        // detected a retransmission of a server response
        // ignore this packet and mark previous as retransmission in progress
        reassembledPacket.setTcpRetransmission(true);
        if (log.isDebugEnabled()) {
          log.debug("DUP: {}", packet);
        }
        return Packet.NULL;
      }
    }

    // save all tcp payload data until we get a signal to push the data up the stack
    if (hasPayload) {
      SequencePayload sequencePayload =
          new SequencePayload(packet.getTcpSeq(), packetPayload, System.currentTimeMillis());
      flows.put(flow, sequencePayload);
    }

    // check if this is a ack for the server response
    if (!isServer && packet.isTcpFlagAck()) {
      // get resassembledPacket packet using client flow
      Packet resassembledPacket = reassembledPackets.remove(packet.getFlow());
      // check if the client ack is for the correct server response.
      if (resassembledPacket != null) {
        // found a resassembledPacket packet waiting to be returned, use the
        // timestamp from the current ack packet for RTT calculation
        // Only do this when NO RETRANSMISSIONS have been detected
        // because we cannot now which packet the client will ack the original packet or any of the
        // retransmissions. See: https://en.wikipedia.org/wiki/Karn%27s_algorithm
        if (!resassembledPacket.isTcpRetransmission()
            && resassembledPacket.nextAck() == packet.getTcpAck()) {
          resassembledPacket.setTcpPacketRtt(packet.getTsMilli() - resassembledPacket.getTsMilli());
        }
        return resassembledPacket;
      }
    }

    // check if this is a end of session (fin) or signal to push data to the
    // application (psh)
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

        // if packet is server response then keep it in reassembledPackets map until we get a
        // ack from the client, we need the timestamp from the client ack for the RTT calculation
        if (isServer) {
          Packet decodedDnsPacket = decodeDnsPayload(packet, packetPayload);
          if (decodedDnsPacket != Packet.NULL) {
            rspPacketCounter++;
            // use the reverse flow to save the packet in reassembledPackets
            // so we can find it again using the the flow of the client.
            reassembledPackets.put(decodedDnsPacket.getReverseFlow(), decodedDnsPacket);
          }
        } else {
          reqPacketCounter++;
          return decodeDnsPayload(packet, packetPayload);
        }
      }
    }

    // do not return any bytes yet to upper protocol decoder.
    return Packet.NULL;
  }

  /**
   * 
   * @param packet
   * @param flow
   * @return true when handshake packet is detected and payload processing should not continue
   */
  private boolean handshake(Packet packet, boolean server) {
    // check if client sent syn
    if (!server && packet.isTcpFlagSyn() && !packet.isTcpFlagAck()) {
      // this is a client syn for a new TCP connection, create handshake and return
      TcpHandshake handshake = new TcpHandshake(packet.getTcpSeq());
      handshake.setSynTs(packet.getTsMilli());
      handshakes.put(packet.getFlow(), handshake);
      return true;
    }
    // check if server sent syn/ack
    else if (server && packet.isTcpFlagSyn() && packet.isTcpFlagAck()) {
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
          // retransmission in the handshake can give incorrect results
          // for rtt measurements
          handshakes.remove(reverseFlow);
        }
      } else if (log.isDebugEnabled()) {
        log.debug("Cannot find handshake for SYN/ACK, maybe a retry?");
      }
      return true;
    }
    // check if client sent ack to complete the handshake
    else if (!server && packet.isTcpFlagAck()) {
      // this could be the final client ack for the handshake
      // or in the case of tcp fast open it can also be the svr reply
      // containing the fast open cookie. ignore fast open handshakes cannot measure
      // rtt for these, see https://tools.ietf.org/html/rfc7413
      TcpHandshake handshake = handshakes.get(packet.getFlow());
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

  private Packet decodeDnsPayload(Packet packet, byte[] payload) {

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
        packet = dnsDecoder.decode((DNSPacket) packet, msgBytes);
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

}
