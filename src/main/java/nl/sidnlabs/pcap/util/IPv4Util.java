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
package nl.sidnlabs.pcap.util;

import java.net.InetAddress;
import nl.sidnlabs.pcap.PcapReaderUtil;

public class IPv4Util {

  private IPv4Util() {}

  public static final int IP_PROTOCOL_OFFSET = 9; // relative to start of IP header
  public static final int IP_SRC_OFFSET = 12; // relative to start of IP header

  public static final int IP_VHL_OFFSET = 0; // relative to start of IP header
  public static final int IP_TTL_OFFSET = 8; // relative to start of IP header

  public static final int IP_DST_OFFSET = 16; // relative to start of IP header
  public static final int IP_ID_OFFSET = 4;

  public static int decodeTTL(byte[] packetData, int ipStart) {
    return packetData[ipStart + IP_TTL_OFFSET] & 0xFF;
  }

  public static byte decodeProtocol(byte[] packetData, int ipStart) {
    return packetData[ipStart + IP_PROTOCOL_OFFSET];
  }

  public static InetAddress decodeSrc(byte[] packetData, int ipStart) {
    return PcapReaderUtil.convertDataToInetAddress(packetData, ipStart + IP_SRC_OFFSET, 4);
  }

  public static InetAddress decodeDst(byte[] packetData, int ipStart) {
    return PcapReaderUtil.convertDataToInetAddress(packetData, ipStart + IP_DST_OFFSET, 4);
  }

  public static int decodeId(byte[] packetData, int ipStart) {
    return PcapReaderUtil.convertShort(packetData, ipStart + IP_ID_OFFSET);
  }

  public static int getInternetProtocolHeaderVersion(byte[] packet, int ipStart) {
    return (packet[ipStart + IP_VHL_OFFSET] >> 4) & 0xF;
  }

  public static int getInternetProtocolHeaderLength(byte[] packet, int ipStart) {
    return (packet[ipStart + IP_VHL_OFFSET] & 0xF) * 4;
  }

}
