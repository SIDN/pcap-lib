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

import nl.sidnlabs.pcap.PcapReaderUtil;

public class UDPUtil {

  private UDPUtil() {}

  public static final int UDP_HEADER_SIZE = 8;
  public static final int UDP_HEADER_LEN_OFFSET = 4;

  public static byte[] extractPayload(byte[] packetData) {
    int length = packetData.length - UDP_HEADER_SIZE;
    byte[] data = new byte[length];
    System.arraycopy(packetData, UDP_HEADER_SIZE, data, 0, length);
    return data;
  }

  /**
   * Get size of udp packet payload
   * 
   * @param packetData data
   * @return length of udp packet
   */
  public static int getUdpLen(byte[] packetData) {
    return PcapReaderUtil.convertShort(packetData, UDP_HEADER_LEN_OFFSET) - UDP_HEADER_SIZE;
  }

}
