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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import nl.sidnlabs.pcap.PcapReader;
import nl.sidnlabs.pcap.PcapReaderUtil;
import nl.sidnlabs.pcap.packet.DNSPacket;
import nl.sidnlabs.pcap.packet.FlowData;
import nl.sidnlabs.pcap.packet.Packet;
import nl.sidnlabs.pcap.packet.SequencePayload;
import nl.sidnlabs.pcap.packet.TCPFlow;
import nl.sidnlabs.pcap.packet.TcpHandshake;
import nl.sidnlabs.pcap.packet.TcpHandshake.HANDSHAKE_STATE;

@Data
@Log4j2
public class TCPDecoder implements Decoder {

  private static final int PROTOCOL_HEADER_TCP_SEQ_OFFSET = 4;
  private static final int PROTOCOL_HEADER_TCP_ACK_OFFSET = 8;
  private static final int TCP_HEADER_DATA_OFFSET = 12;
  private static final int PROTOCOL_HEADER_WINDOW_SIZE_OFFSET = 14;
  private static final int PROTOCOL_HEADER_OPTIONS_OFFSET = 20;
  // last 5 bits of the 1st byte of the option are for the option number
  private static final int PROTOCOL_HEADER_OPTION_LEN_MASK = 0b00011111;
  private static final int PROTOCOL_HEADER_OPTION_TIMESTAMP = 8;

  private static final int TCP_DNS_LENGTH_PREFIX = 2;

  private DNSDecoder dnsDecoder;

  private Map<TCPFlow, FlowData> flows = new HashMap<>();
  private Map<TCPFlow, TcpHandshake> handshakes = new HashMap<>();
  // keep reassembled packets until a ack is received and the ack time can be added to the packet
  private Map<TCPFlow, Packet> reassembledPackets = new HashMap<>();

  private int packetCounter = 0;
  private int reqPacketCounter = 0;
  private int rspPacketCounter = 0;
  private int dnsRspMsgCounter = 0;
  private int dnsReqMsgCounter = 0;

  public TCPDecoder() {
    this(false);
  }

  public TCPDecoder(boolean allowfail) {
    dnsDecoder = new DNSDecoder(allowfail);
  }

  /**
   * decode the packetdata
   * 
   * @param packet network packet
   * @param packetData data to assemble
   * @return reassembled packet of NULL packet
   */
  @Override
  public Packet reassemble(Packet packet, byte[] packetData) {
    packetCounter += 1;

    if (log.isDebugEnabled()) {
      log.debug("Received {} packets", packetCounter);
    }

    byte[] packetPayload = decode(packet, packetData);

    if (!isDNS(packet)) {
      // not a dns packet, ignore
      return Packet.NULL;
    }

    if (packet.isTcpFlagRst()) {
      // reset flag is set, connection should be reset, clear all state
      if (log.isDebugEnabled()) {
        log.debug("Connection RESET for src: {} dst: {}", packet.getSrc(), packet.getDst());
      }
      TCPFlow flow = packet.getFlow();
      handshakes.remove(flow);
      flows.remove(flow);
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
        // detected a duplicate server response
        reassembledPacket.setTcpRetransmission(true);
        if (log.isDebugEnabled()) {
          log
              .debug("Ignoring duplicate packet for src: {} dst: {}", packet.getSrc(),
                  packet.getDst());
        }
        return Packet.NULL;
      }
    }

    // check if this is a ack for the server response
    if (!isServer && packet.isTcpFlagAck()) {
      // get resassembledPacket packet using client flow
      Packet resassembledPacket = reassembledPackets.get(packet.getFlow());
      // check if the client ack is for the correct server response.
      if (resassembledPacket != null) {
        // found a resassembledPacket packet waiting to be returned, use the
        // timestamp of the current ack packet for RTT calculation
        // Only do this when NO RETRANSMISSIONS have been detected
        // because we cannot now which packet the client will ack the original packet or any of the
        // retransmissions. See: https://en.wikipedia.org/wiki/Karn%27s_algorithm
        if (!resassembledPacket.isTcpRetransmission()
            && resassembledPacket.nextAck() == packet.getTcpAck()) {
          resassembledPacket
              .setTcpPacketRtt((int) (packet.getTsMilli() - resassembledPacket.getTsMilli()));
        }

        if (packetPayload.length == 0) {
          // empty request, just return the prev reassembled response with the rtt set.
          return reassembledPackets.remove(packet.getFlow());
        }

        // request packet has more dns request to decode, continue with tcp processing
      }
    }

    // FlowData is used to keep a list of all data-segments (sequences) linked to the current flow
    // can be null at this point
    FlowData fd = flows.get(flow);
    if (fd == null) {
      if (packetPayload.length < TCP_DNS_LENGTH_PREFIX) {
        // first packet did not have enough data (2-bytes) for the dns message length prefix
        // probably malformed packet, ignore packet
        return Packet.NULL;
      }
      // this is the 1st segment for this flow, create new FlowData
      fd = new FlowData();
      flows.put(flow, fd);
    }
    // save all tcp payload data until we get a signal to push the data up the stack
    if (hasPayload) {
      SequencePayload sequencePayload =
          new SequencePayload(packet.getTcpSeq(), packetPayload, System.currentTimeMillis(), flow);

      // add the segment/sequence to flowdata
      fd.addPayload(sequencePayload);
      if (fd.size() == 1) {
        // this is the first part of the tcp flow, set the
        // - size of the next dns message
        // - total bytes available (sum of all received sequences) for current flow
        fd.setNextDnsMsgLen(dnsMessageLen(packetPayload, 0));
        fd.setBytesAvail(packetPayload.length);
      } else {
        fd.setBytesAvail(fd.getBytesAvail() + packetPayload.length);
      }
    }

    if (packet.isTcpFlagFin() && !isNextPayloadAvail(fd)) {
      // got end of tcp stream but not enough data to decode dns packet.
      // ignore the leftover data
      flows.remove(flow);
      return Packet.NULL;
    }

    // check if this is a end of session (fin) or signal to push data to the
    // application (psh)
    if (packet.isTcpFlagFin() || packet.isTcpFlagPsh() || isNextPayloadAvail(fd)) {

      // if the PSH flag is set, this does not mean enough bytes ares received to
      // be able to decode the DNS data. If not enough bytes avail, wait for more packets.

      if (!fd.isNextPayloadAvail()) {
        // uhoh not enough data, stop here and wait for next packet
        return Packet.NULL;
      }

      // remove flow from flow map and process the flow data
      flows.remove(flow);
      if (fd != null && fd.size() > 0) {

        packet.setReassembledTCPFragments(fd.size());
        // get total size of the dns bytes reveived this can be for multiple packets
        // and the last dns message might not be complete yet.
        packetPayload = new byte[fd.getBytesAvail()];

        // link all flow sequences into a ordered list without gaps.
        List<SequencePayload> linkSequencePayloads =
            linkSequencePayloads(fd.getSortedPayloads(), packet);

        // check if there are still enough bytes available, some duplicate sequence
        // might have been dropped and we need to update the flowdata
        fd.setBytesAvail(linkSequencePayloads.stream().mapToInt(s -> s.getBytes().length).sum());
        if (linkSequencePayloads.isEmpty() || !fd.isNextPayloadAvail()) {
          // uhoh not enough data, stop here and wait for next packet
          return Packet.NULL;
        }

        // copy all the payload bytes
        int destPos = 0;
        SequencePayload prev = null;
        for (SequencePayload seqPayload : linkSequencePayloads) {
          System
              .arraycopy(seqPayload.getBytes(), 0, packetPayload, destPos,
                  seqPayload.getBytes().length);
          destPos += seqPayload.getBytes().length;

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
          // server sending data
          byte[] remainder = decodeDnsPayload(packet, packetPayload);
          if (log.isDebugEnabled()) {
            dnsRspMsgCounter += ((DNSPacket) packet).getMessageCount();
            log.debug("Decoded {} response messages", dnsRspMsgCounter);
          }

          if (remainder.length > 0 && prev != null) {
            createNewFlowWithRemainer(flow, remainder, prev, fd.getLastSize());
          }

          if (packet != Packet.NULL) {
            rspPacketCounter++;
            // use the reverse flow to save the packet in reassembledPackets
            // so we can find it again using the the flow of the client.

            // if a reassembled packet is already present for the current flow
            // then replace the packet with the new packet and return the previously
            // reassembled packet
            Packet prevPacket = reassembledPackets.remove(packet.getReverseFlow());

            // do not return a reassembled server response until the client has
            // acked it, so the rtt can be determined.
            reassembledPackets.put(packet.getReverseFlow(), packet);

            if (log.isDebugEnabled()) {
              log
                  .debug("Reassembled packet with {} DNS messages",
                      ((DNSPacket) packet).getMessageCount());
            }

            // prev packet must be returned now, can only keep 1 server response
            // for each flow. the packet rtt might not yet have been set. because
            // the client has not yet sent an ack
            return prevPacket != null ? prevPacket : Packet.NULL;
          }
        } else {
          // client sending data
          reqPacketCounter++;
          byte[] remainder = decodeDnsPayload(packet, packetPayload);

          if (log.isDebugEnabled()) {
            dnsReqMsgCounter += ((DNSPacket) packet).getMessageCount();
            log.debug("Decoded {} request messages", dnsReqMsgCounter);
          }

          if (remainder.length > 0 && prev != null) {
            createNewFlowWithRemainer(flow, remainder, prev, fd.getLastSize());
          }

          // return decoded packet
          return packet;
        }
      }
    }

    // do not return any bytes yet to upper protocol decoder.
    return Packet.NULL;
  }

  public byte[] decode(Packet packet, byte[] packetData) {
    packet
        .setSrcPort(
            PcapReaderUtil.convertShort(packetData, Decoder.PROTOCOL_HEADER_SRC_PORT_OFFSET));
    packet
        .setDstPort(
            PcapReaderUtil.convertShort(packetData, Decoder.PROTOCOL_HEADER_DST_PORT_OFFSET));

    int tcpOrUdpHeaderSize = getTcpHeaderLength(packetData);
    if (tcpOrUdpHeaderSize == -1) {
      return new byte[0];
    }
    packet.setTcpHeaderLen(tcpOrUdpHeaderSize);

    // Store the sequence and acknowledgement numbers --M
    packet.setTcpSeq(PcapReaderUtil.convertUnsignedInt(packetData, PROTOCOL_HEADER_TCP_SEQ_OFFSET));
    packet.setTcpAck(PcapReaderUtil.convertUnsignedInt(packetData, PROTOCOL_HEADER_TCP_ACK_OFFSET));
    // Flags stretch two bytes starting at the TCP header offset
    int flags = PcapReaderUtil
        .convertShort(
            new byte[] {packetData[TCP_HEADER_DATA_OFFSET], packetData[TCP_HEADER_DATA_OFFSET + 1]})
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
        .setTcpWindowSize(
            PcapReaderUtil.convertShort(packetData, PROTOCOL_HEADER_WINDOW_SIZE_OFFSET));

    int payloadLength = packetData.length - tcpOrUdpHeaderSize;

    byte[] data = PcapReaderUtil.readPayload(packetData, tcpOrUdpHeaderSize, payloadLength);

    packet.setPayloadLength(payloadLength);
    // total length of packet
    packet.setLen(packetData.length);

    // decodeOptions(packet, packetData, tcpOrUdpHeaderSize);
    return data;
  }

  // OLD TCP options decode code, leave for now as an example for when we might
  // want to do something with the tcp options
  // /**
  // * try to locate and decode the timestamp option
  // *
  // * @param packet the current packet
  // * @param packetData the current packet data
  // * @param tcpHeaderSize the tcp header size
  // */
  // private void decodeOptions(Packet packet, byte[] packetData, int tcpHeaderSize) {
  // if (tcpHeaderSize > PROTOCOL_HEADER_OPTIONS_OFFSET) {
  // // tcp header is > 20 bytes, meanign there are tcp options present
  // int pos = PROTOCOL_HEADER_OPTIONS_OFFSET;
  // int option = -1;
  // // scan through options until reached end of options or end-options found or
  // // timestamp options found
  // while (pos < tcpHeaderSize && option != 0) {
  // option = PROTOCOL_HEADER_OPTION_LEN_MASK & (0xFF & packetData[pos++]);
  // // option 0 and 1 do not have length field
  // if (option > 1) {
  // int len = 0xFF & packetData[pos++];
  // if (option == PROTOCOL_HEADER_OPTION_TIMESTAMP) {
  // byte[] ts = new byte[4];
  // System.arraycopy(packetData, pos, ts, 0, ts.length);
  // packet.setTcpOptionTSval(readUnsignedInt(ts));
  // System.arraycopy(packetData, pos + 4, ts, 0, ts.length);
  // packet.setTcpOptionTSecr(readUnsignedInt(ts));
  // // stop processing options, only interested in the TS option
  // break;
  // }
  // // goto to next option postion
  // pos += (len - 2);
  // }
  // }
  // }
  // }

  public long readUnsignedInt(byte[] buf) {
    int byte1 = (0xFF & buf[0]);
    int byte2 = (0xFF & buf[1]);
    int byte3 = (0xFF & buf[2]);
    int byte4 = (0xFF & buf[3]);

    return ((long) (byte1 << 24 | byte2 << 16 | byte3 << 8 | byte4)) & 0xFFFFFFFFL;
  }


  /**
   * Create a validated list of TCP data segments where each segments is linked to the next, based
   * on the sequence numbers
   * 
   * @param seqPayloads data segments to link
   * @param packet current packet
   * @return list of linked segments, can be empty list in case of broken seq chain, never null
   */
  private List<SequencePayload> linkSequencePayloads(List<SequencePayload> seqPayloads,
      Packet packet) {

    SequencePayload prev = null;
    for (SequencePayload seqPayload : seqPayloads) {
      if (prev != null && !seqPayload.linked(prev)) {
        log
            .warn("Packet src: " + packet.getSrc() + " dst: " + packet.getDst()
                + " has Broken sequence chain between " + seqPayload + " and " + prev);
        seqPayload.setIgnore(true);
        return Collections.emptyList();
      }
      prev = seqPayload;
    }

    return seqPayloads;
  }

  private boolean isNextPayloadAvail(FlowData fd) {
    return fd != null && fd.isNextPayloadAvail();
  }

  /**
   * Add a new flowdata obj to the flows map, using the leftover bytes. these are the bytes that can
   * not yet be decoded because more data is required.
   * 
   * @param flow current flow
   * @param remainder the leftover bytes
   * @param lastPayload the last sequence, this will become the 1st sequence now
   * @param lastSize the payload size of the last packet
   */
  private void createNewFlowWithRemainer(TCPFlow flow, byte[] remainder,
      SequencePayload lastPayload, long lastSize) {
    // set the remaining bytes as last payload
    lastPayload.setBytes(remainder);

    FlowData fd = new FlowData();
    // update the flow details
    fd.setBytesAvail(remainder.length);
    fd.setNextDnsMsgLen(dnsMessageLen(remainder, 0));
    fd.addPayload(lastPayload);
    fd.setLastSize(lastSize);
    flows.put(flow, fd);
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
      if (handshakes.containsKey(packet.getFlow())) {
        // found SYN packet while a SYN was already received, probably retransmission of
        // SYN packet by client, ignore this handshake.
        handshakes.remove(packet.getFlow());
        return true;
      }
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

  private int getTcpHeaderLength(byte[] packet) {
    if (TCP_HEADER_DATA_OFFSET < packet.length) {
      return ((packet[TCP_HEADER_DATA_OFFSET] >> 4) & 0xF) * 4;
    }
    // invalid header
    return -1;
  }

  private int dnsMessageLen(byte[] payload, int payloadIndex) {
    if (payload == null || payload.length < 2) {
      if (log.isDebugEnabled()) {
        log
            .debug("Reading DNS message len from failed failed, only {} bytes available",
                payload.length);
      }

      return 0;
    }
    byte[] lenBytes = new byte[2];
    System.arraycopy(payload, payloadIndex, lenBytes, 0, 2);
    return PcapReaderUtil.convertShort(lenBytes);
  }

  private byte[] decodeDnsPayload(Packet packet, byte[] payload) {
    /*
     * TCP flow may contain multiple dns messages break the TCP flow into the individual dns msg
     * blocks, every dns msg has a 2 byte msg prefix need at least the 2 byte len prefix to start.
     */
    int payloadIndex = 0;
    while ((payload.length > TCPDecoder.TCP_DNS_LENGTH_PREFIX)
        && (payloadIndex + TCPDecoder.TCP_DNS_LENGTH_PREFIX < payload.length)) {
      int msgLen = dnsMessageLen(payload, payloadIndex);
      // add the 2byte msg len
      payloadIndex += 2;
      if (msgLen > 0 && (payloadIndex + msgLen) <= payload.length) {
        byte[] msgBytes = new byte[msgLen];
        System.arraycopy(payload, payloadIndex, msgBytes, 0, msgLen);
        packet = dnsDecoder.decode((DNSPacket) packet, msgBytes);
        // add the msg len to the index
        payloadIndex += msgLen;
      } else {
        // dns msg requires more bytes than are available
        // might be partial data for the next dns msg
        // return the bytes, mkae sure to also include the 2-byte dns msg len prefix
        int index = payloadIndex - 2;
        byte[] remainingBytes = new byte[payload.length - index];
        System.arraycopy(payload, index, remainingBytes, 0, remainingBytes.length);

        // return any bytes that could not be decoded because not enough bytes are available yet.
        // this bytes will be combined with the bytes from the next packets from the pcap stream
        return remainingBytes;
      }
    }
    if (log.isDebugEnabled() && ((DNSPacket) packet).getMessageCount() > 1) {
      log.debug("multiple msg in TCP stream");
    }

    // return any bytes leftover, might be partial data foir the next dns msg
    return new byte[0];
  }

  public void clearCache(int cacheTTL) {
    // clear tcp flows with expired packets
    List<TCPFlow> expiredList = new ArrayList<>();
    long now = System.currentTimeMillis();
    for (Entry<TCPFlow, FlowData> entry : flows.entrySet()) {
      for (SequencePayload sequencePayload : entry.getValue().getPayloads()) {
        if ((sequencePayload.getTime() + cacheTTL) <= now) {
          expiredList.add(entry.getKey());
          break;
        }
      }
    }

    log.info("TCP flow cache size: " + flows.size());
    log.info("Expired (to be removed) TCP flows: " + expiredList.size());

    // remove flows with expired packets
    expiredList.stream().forEach(s -> flows.remove(s));
  }

  public boolean hasReassembledPackets() {
    return !reassembledPackets.isEmpty();
  }

  public Packet getNextReassmbledPacket() {
    TCPFlow f = reassembledPackets.keySet().iterator().next();
    return f != null ? reassembledPackets.remove(f) : Packet.NULL;
  }

}
