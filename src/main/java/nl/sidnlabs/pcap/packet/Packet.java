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
package nl.sidnlabs.pcap.packet;

import lombok.Data;
import nl.sidnlabs.pcap.decoder.IPDecoder;

/**
 * Packet contains a combination of IP layer and UDP/TCP/DNS layer data Fragmented IP is joined into
 * a single Packet object Fragmented UDP is joined into a single Packet object TCP session with
 * multiple DNS queries in a stream before the PSH or FIN will cause multiple DNS messages to get
 * added to the Packet object.
 * 
 */
@Data
public class Packet {

  public static final Packet NULL = new Packet();

  // network
  protected int len;
  // time in seconds
  protected long tsSec;
  // time in micros relative to tsSec (in secs)
  protected long tsMicro;
  // time in millis when packet was sent ( tsSec + tsmicros)
  protected long tsMilli;
  // ip
  protected long ipId;
  protected int ttl;
  protected int ipVersion;
  protected int ipHeaderLen;
  protected short protocol;
  protected String src;
  protected String dst;
  protected long fragOffset;
  protected boolean fragmented;
  protected boolean lastFragment;
  // ip fragments
  protected int reassembledFragments;
  // ipv6
  protected boolean fragmentFlagM;
  // tcp
  protected int reassembledTCPFragments;
  protected int srcPort;
  protected int dstPort;
  protected int tcpflow;
  protected int tcpHeaderLen;
  protected long tcpSeq;
  protected long tcpAck;
  protected boolean tcpFlagNs;
  protected boolean tcpFlagCwr;
  protected boolean tcpFlagEce;
  protected boolean tcpFlagUrg;
  protected boolean tcpFlagAck;
  protected boolean tcpFlagPsh;
  protected boolean tcpFlagRst;
  protected boolean tcpFlagSyn;
  protected boolean tcpFlagFin;
  protected int tcpWindowSize;

  private int totalLength;
  protected int payloadLength;

  // if this is a tcp packet and a handshake has been completed
  // then tcpHandshake will contain the timestamps
  protected TcpHandshake tcpHandshake;
  // time in millis between time packet was sent by server
  // and when ack for packet was received in case of TCP use( tsSec + tsmicros)
  protected int tcpPacketRtt = -1;
  private boolean tcpRetransmission;

  private TCPFlow flow;
  private TCPFlow reverseFlow;


  /**
   * Get FLOW from Client to Server
   * 
   * @return TCPFlow
   */
  public TCPFlow getFlow() {
    if (flow == null) {
      flow = new TCPFlow(src, srcPort, dst, dstPort, protocol);
    }
    return flow;
  }

  /**
   * Get FLOW from Server to Client
   * 
   * @return TCPFlow
   */
  public TCPFlow getReverseFlow() {
    if (reverseFlow == null) {
      reverseFlow = new TCPFlow(dst, dstPort, src, srcPort, protocol);
    }
    return reverseFlow;
  }


  public Datagram getDatagram() {
    return new Datagram(getSrc(), getDst(), getIpId(), String.valueOf(getProtocol()),
        System.currentTimeMillis());
  }


  public boolean isIPv4() {
    return getIpVersion() == IPDecoder.IP_PROTOCOL_VERSION_4;
  }

  public boolean isIPv6() {
    return getIpVersion() == IPDecoder.IP_PROTOCOL_VERSION_6;
  }

  public boolean hasPacketRtt() {
    return tcpPacketRtt != -1;
  }

  /**
   * Calculate next sequence number
   * 
   * @return sequencenumber expected in the next ack for this packet
   */
  public long nextAck() {
    return tcpSeq + payloadLength;
  }

}
