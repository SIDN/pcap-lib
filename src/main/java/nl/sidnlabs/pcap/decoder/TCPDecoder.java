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

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import lombok.Getter;
import lombok.Setter;
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

@Getter
@Setter
@Log4j2
public class TCPDecoder implements Decoder {

  private static final int PROTOCOL_HEADER_TCP_SEQ_OFFSET = 4;
  private static final int PROTOCOL_HEADER_TCP_ACK_OFFSET = 8;
  private static final int TCP_HEADER_DATA_OFFSET = 12;
  private static final int PROTOCOL_HEADER_WINDOW_SIZE_OFFSET = 14;
//  private static final int PROTOCOL_HEADER_OPTIONS_OFFSET = 20;
//  // last 5 bits of the 1st byte of the option are for the option number
//  private static final int PROTOCOL_HEADER_OPTION_LEN_MASK = 0b00011111;
//  private static final int PROTOCOL_HEADER_OPTION_TIMESTAMP = 8;

  private static final int TCP_DNS_LENGTH_PREFIX = 2;


  private DNSDecoder dnsDecoder;

  private Map<TCPFlow, FlowData> flows = new HashMap<>();
  private Map<TCPFlow, TcpHandshake> handshakes = new HashMap<>();

  private int packetCounter = 0;
  private int reqPacketCounter = 0;
  private int rspPacketCounter = 0;
  private int dnsRspMsgCounter = 0;
  private int dnsReqMsgCounter = 0;

  // create default 2k byte buffer for decoding
  private ByteBuffer packetPayload = ByteBuffer.allocate(1024 * 2);
  // shared buffer for dns payload decoding
  private byte[] sharedDnsBuffer = new byte[1024 * 2];

  private long lastPacketTs = 0;

  public TCPDecoder(DNSDecoder dnsDecoder) {
    this.dnsDecoder = dnsDecoder;
  }

  private FlowData removeFlow(TCPFlow flow) {
    return flows.remove(flow);
  }

  private void addFlow(TCPFlow flow, FlowData fd) {
    flows.put(flow, fd);
  }

  private FlowData lookupFlow(TCPFlow flow) {
    return flows.get(flow);
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
      log.debug("Received {} packets", Integer.valueOf(packetCounter));
    }

    packetPayload = decode(packet, packetData);
    lastPacketTs = packet.getTsMilli();

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
      removeFlow(flow);
      return Packet.NULL;
    }

    // get the flow details for this packet
    TCPFlow flow = packet.getFlow();
    boolean isServer = packet.getSrcPort() == PcapReader.DNS_PORT;
    // boolean hasPayload = packetPayload.capacity() > 0;

    if (handshake(packet, isServer) || (packet.isTcpFlagAck() && !packetPayload.hasRemaining())) {
      // packet is part of handshake or ack
      // do not continue because no payload data
      return Packet.NULL;
    }

    // FlowData is used to keep a list of all data-segments (sequences) linked to the current flow
    // can be null at this point
    FlowData fd = lookupFlow(flow);
    if (fd == null) {
      if (packetPayload.remaining() < TCP_DNS_LENGTH_PREFIX) {
        // first packet did not have enough data (2-bytes) for the dns message length prefix
        // probably malformed packet, ignore packet
        return Packet.NULL;
      }
      // this is the 1st segment for this flow, create new FlowData
      fd = new FlowData();
      addFlow(flow, fd);
    }

    // save all tcp payload data until we get a signal to push the data up the stack
    if (packetPayload.hasRemaining()) {
      byte[] bytes = new byte[packetPayload.limit()];
      packetPayload.get(bytes);
      SequencePayload sequencePayload =
          new SequencePayload(packet.getTcpSeq(), bytes, packet.getTsMilli(), flow);

      if (log.isDebugEnabled()) {
        log.debug("reassemble, tcp bytes len: {}", Integer.valueOf(packetPayload.limit()));
      }

      // add the segment/sequence to flowdata
      fd.addPayload(sequencePayload);
    }

    if (packet.isTcpFlagFin() && fd != null && !fd.isMinPayloadAvail()) {
      // got end of tcp stream but not enough data to decode dns packet.
      // ignore the leftover data
      removeFlow(flow);
      return Packet.NULL;
    }

    // check if this is a end of session (fin) or signal to push data to the
    // application (psh)
    if (packet.isTcpFlagFin() || packet.isTcpFlagPsh()
        || packet.isTcpFlagAck() /* || isNextPayloadAvail(fd) */) {

      // if the PSH flag is set, this does not mean enough bytes ares received to
      // be able to decode the DNS data. If not enough bytes avail, wait for more packets.

      if (!fd.isMinPayloadAvail()) {
        // uhoh not enough data, stop here and wait for next packet
        return Packet.NULL;
      }

      // remove flow from flow map and process the flow data
      removeFlow(flow);
      if (fd != null && fd.size() > 0) {

        packet.setReassembledTCPFragments(fd.size());
        List<SequencePayload> sequencePayloads = getFlowPayloadsAsList(fd, packet);

        if (sequencePayloads.isEmpty() || !fd.isMinPayloadAvail()) {
          // uhoh not enough data, stop here and wait for next packet
          return Packet.NULL;
        }

        // create a buffer that contains all byte[] arrays from the
        // sequencePayloads. DO NOT copy byte[] into new array
        // the allocate and copy will take too much resources.
        ChainBuffer combinedBuffer = mergePayloads(sequencePayloads);
        SequencePayload lastSequencePayload = sequencePayloads.get(sequencePayloads.size() - 1);

        // return the data for processing up the stack
        // also add the tcp handshake (if found) to the first packet
        TcpHandshake handshake = handshakes.remove(flow);
        if (handshake != null && HANDSHAKE_STATE.ACK_RECV == handshake.getState()) {
          // add handshake to the first packet after the handshake was completed, must be in state
          // HANDSHAKE_STATE.ACK_RECV
          packet.setTcpHandshakeRTT(handshake.rtt());
        }

        // if packet is server response then keep it in reassembledPackets map until we get a
        // ack from the client, we need the timestamp from the client ack for the RTT calculation
        if (isServer) {
          // server sending data
          ChainBuffer remainder = decodeDnsPayload(packet, combinedBuffer);
          dnsRspMsgCounter += ((DNSPacket) packet).getMessageCount();

          if (remainder.readableBytes() > 0 && lastSequencePayload != null) {
            // make a copy of bytes because now they are in the shared buffer
            createNewFlowWithRemainder(flow, remainder, lastSequencePayload);
          }

          if (packet != Packet.NULL) {
            rspPacketCounter++;

            if (log.isDebugEnabled()) {
              log
                  .debug("Reassembled packet with {} DNS messages",
                      Integer.valueOf(((DNSPacket) packet).getMessageCount()));
            }

            return packet;
          }
        } else {
          // client sending data
          reqPacketCounter++;
          ChainBuffer remainder = decodeDnsPayload(packet, combinedBuffer);
          dnsReqMsgCounter += ((DNSPacket) packet).getMessageCount();

          if (remainder.readableBytes() > 0 && lastSequencePayload != null) {
            createNewFlowWithRemainder(flow, remainder, lastSequencePayload);
          }

          // return decoded packet
          return packet;
        }
      }
    }

    // do not return any bytes yet to upper protocol decoder.
    return Packet.NULL;
  }

  private List<SequencePayload> getFlowPayloadsAsList(FlowData fd, Packet packet) {
    if (fd.size() == 1) {
      return fd.getPayloads();
    }

    // link all flow sequences into a ordered list without gaps.
    return linkSequencePayloads(fd.getSortedPayloads(), packet);
  }

  /**
   * Create new ChainBuffer with all buffers from the sequencePayloads
   * 
   * @param sequencePayloads
   * @return ChainBuffer
   */
  private ChainBuffer mergePayloads(List<SequencePayload> sequencePayloads) {
    ChainBuffer buff = null;

    for (SequencePayload sp : sequencePayloads) {
      if (sp.hasBuffer()) {
        // can only be first payload, switch buffers
        buff = sp.getBuffer();
      } else {

        if (buff == null) {
          buff = new ChainBuffer();
        }

        buff.addLast(sp.getBytes());
      }
    }

    return buff;
  }

  public ByteBuffer decode(Packet packet, byte[] packetData) {
    packet
        .setSrcPort(
            PcapReaderUtil.convertShort(packetData, Decoder.PROTOCOL_HEADER_SRC_PORT_OFFSET));
    packet
        .setDstPort(
            PcapReaderUtil.convertShort(packetData, Decoder.PROTOCOL_HEADER_DST_PORT_OFFSET));

    int tcpOrUdpHeaderSize = getTcpHeaderLength(packetData);
    if (tcpOrUdpHeaderSize == -1) {
      return ByteBuffer.allocate(0);
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

    packet.setPayloadLength(payloadLength);
    // total length of packet
    packet.setLen(packetData.length);

    return PcapReaderUtil
        .readPayloadToBuffer(packetData, tcpOrUdpHeaderSize, payloadLength, packetPayload);

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
      if ( prev != null && !seqPayload.linked(prev)) {
         if (log.isDebugEnabled()) {
        log
            .debug("Packet src: " + packet.getSrc() + " dst: " + packet.getDst()
                + " has Broken sequence chain between " + seqPayload + " and " + prev);
         }
        return Collections.emptyList();
      }
      prev = seqPayload;
    }

    return seqPayloads;
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
  private void createNewFlowWithRemainder(TCPFlow flow, ChainBuffer remainder,
      SequencePayload lastPayload) {

    // remove already decoded data
    remainder.clean();

    // set the remaining bytes as last payload
    lastPayload.setBuffer(remainder);

    FlowData fd = new FlowData();
    // update the flow details
    // fd.setBytesAvail(remainder.length);
    fd.addPayload(lastPayload);
    // fd.setLastSize(lastSize);
    addFlow(flow, fd);
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

  private int dnsMessageLen(ChainBuffer payload) {
    if (payload == null || payload.readableBytes() < 2) {
      if (log.isDebugEnabled()) {
        log
            .debug("Reading DNS message len from failed failed, only {} bytes remaining",
                Integer.valueOf(payload.readableBytes()));
      }

      return 0;
    }

    return payload.getShort();
  }

  private ChainBuffer decodeDnsPayload(Packet packet, ChainBuffer buffer) {
    /*
     * TCP flow may contain multiple dns messages break the TCP flow into the individual dns msg
     * blocks, every dns msg has a 2 byte msg prefix need at least the 2 byte len prefix to start.
     */

    while (buffer.readableBytes() > TCPDecoder.TCP_DNS_LENGTH_PREFIX) {

      int len = dnsMessageLen(buffer);

      if (len > 0 && (buffer.readableBytes() >= len)) {

        byte[] data = null;
        int offset = 0;

        // for improved performance try to avoid to create new byte[] and copying
        // the data bytes to this buffer. Try to use the backing buffer of the ChainBuffer

        if (buffer.readableBytesCurrentBuffer() >= len) {
          // ChainBuffer uses single byte[] for data we need
          // prevent copy data to sharedDnsBuffer buffer and just use
          // the backing buffer from the ChainBuffer
          data = buffer.currentBuffer();
          offset = buffer.getOffset();
          // make sure to advance the position of the offset
          buffer.position(buffer.position() + len);
          // the buffer also includes the 2 length bytes before the actual data bytes
          // <byte><byte>[data]
          // decoding must start at current buffer offset (after len bytes) and end at length +2.
          len += 2;
        } else {
          // ChainBuffer uses multiple byte[] for data we need
          // copy data into shared buffer, offset = 0
          if (sharedDnsBuffer.length < len) {
            sharedDnsBuffer = new byte[len];
          }

          buffer.gets(sharedDnsBuffer, 0, len);
          data = sharedDnsBuffer;
        }

        dnsDecoder.decode((DNSPacket) packet, data, offset, len);
      } else {
        // dns msg requires more bytes than are available
        // might be partial data for the next dns msg
        // return the bytes, make sure to also include the 2-byte dns msg len prefix
        buffer.position(buffer.position() - 2);
        break;
      }
    }

    if (log.isDebugEnabled() && ((DNSPacket) packet).getMessageCount() > 1) {
      log
          .debug("multiple msg in TCP stream: {}",
              Integer.valueOf(((DNSPacket) packet).getMessageCount()));
    }

    return buffer;
  }

  public void clearCache(int cacheTTL) {
    // clear tcp flows with expired packets
    List<TCPFlow> expiredList = new ArrayList<>();
    long max = lastPacketTs - cacheTTL;
    for (Entry<TCPFlow, FlowData> entry : flows.entrySet()) {
      // if 1 payload is expired then remove entire flow.
      for (SequencePayload sequencePayload : entry.getValue().getPayloads()) {
        if ((sequencePayload.getTime()) < max) {
          expiredList.add(entry.getKey());
          break;
        }
      }
    }

    log.info("------------- TCP Decoder Cache Stats --------------------");
    log.info("TCP flow cache size: " + flows.size());
    log.info("Expired (to be removed) TCP flows: " + expiredList.size());

    // remove flows with expired packets
    expiredList.stream().forEach(s -> removeFlow(s));
  }

  public void printStats() {
    log.info("---------------------- TCP Decoder Stats -----------------");
    log.info("Packets total: {}", Integer.valueOf(packetCounter));
    log.info("Request: {}", Integer.valueOf(reqPacketCounter));
    log.info("Response: {}", Integer.valueOf(rspPacketCounter));
    log.info("DNS replies: {}", Integer.valueOf(dnsRspMsgCounter));
    log.info("DNS queries: {}", Integer.valueOf(dnsReqMsgCounter));
  }

  @Override
  public void reset() {
    packetCounter = 0;
    reqPacketCounter = 0;
    rspPacketCounter = 0;
    dnsRspMsgCounter = 0;
    dnsReqMsgCounter = 0;

    dnsDecoder.reset();
  }

}
