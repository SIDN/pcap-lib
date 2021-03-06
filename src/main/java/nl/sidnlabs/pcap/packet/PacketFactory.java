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

/**
 * Create a packet object based on the protocol number.
 *
 */
public class PacketFactory {

  public static final int PROTOCOL_TCP = 6;
  public static final int PROTOCOL_UDP = 17;
  public static final int PROTOCOL_ICMP_V4 = 1;
  public static final int PROTOCOL_ICMP_V6 = 58;

  private PacketFactory() {}

  public static Packet create(byte protocol) {
    if ((protocol == PROTOCOL_ICMP_V4) || (protocol == PROTOCOL_ICMP_V6)) {
      return new ICMPPacket(protocol);
    } else if ((protocol == PROTOCOL_UDP) || (protocol == PROTOCOL_TCP)) {
      return new DNSPacket(protocol);
    } else {
      return Packet.NULL;
    }
  }

}
