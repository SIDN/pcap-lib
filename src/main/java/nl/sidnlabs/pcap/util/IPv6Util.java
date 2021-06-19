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
import nl.sidnlabs.pcap.packet.Packet;


public class IPv6Util {

  private IPv6Util() {}

  public static final int IPV6_HEADER_SIZE = 40;
  public static final int IPV6_PAYLOAD_LEN_OFFSET = 4; // relative to start of IP header
  public static final int IPV6_HOPLIMIT_OFFSET = 7; // relative to start of IP header
  public static final int IPV6_NEXTHEADER_OFFSET = 6; // relative to start of IP header
  public static final int IPV6_SRC_OFFSET = 8; // relative to start of IP header
  public static final int IPV6_DST_OFFSET = 24; // relative to start of IP header
  public static final int IPV6_FRAGMENT_EXTENTION_TYPE = 44;
  public static final int IPV6_FRAGMENT_EXTENTION_SIZE = 8;
  // the offset from the start of the fragment extension header
  public static final int IPV6_FRAGMENT_OFFSET = 2;
  public static final int IPV6_MFLAG_OFFSET = 3;
  public static final int IPV6_ID_OFFSET = 4;

  public static byte decodeProtocol(byte[] packetData, int ipStart) {
    byte protocol = packetData[ipStart + IPV6_NEXTHEADER_OFFSET];
    if (protocol == IPV6_FRAGMENT_EXTENTION_TYPE) {
      // fragment header founf, get actual proto from the header
      protocol = packetData[ipStart + IPV6_HEADER_SIZE];
    }

    return protocol;
  }

  public static int decodeTTL(byte[] packetData, int ipStart) {
    return packetData[ipStart + IPV6_HOPLIMIT_OFFSET] & 0xFF;
  }

  // public static InetAddress decodeAddress(byte[] packetData, int ipStart) {
  // return PcapReaderUtil.convertDataToInetAddress(packetData, ipStart + IPV6_SRC_OFFSET, 16);
  // }

  public static InetAddress decodeSrc(byte[] packetData, int ipStart) {
    return PcapReaderUtil.convertDataToInetAddress(packetData, ipStart + IPV6_SRC_OFFSET, 16);
  }

  public static InetAddress decodeDst(byte[] packetData, int ipStart) {
    return PcapReaderUtil.convertDataToInetAddress(packetData, ipStart + IPV6_DST_OFFSET, 16);
  }

  public static long decodeId(byte[] packetData, int ipStart) {
    int nxtHdr = packetData[ipStart + IPV6_NEXTHEADER_OFFSET];
    if (nxtHdr == IPV6_FRAGMENT_EXTENTION_TYPE) {
      return PcapReaderUtil
          .convertUnsignedInt(packetData, ipStart + IPV6_HEADER_SIZE + IPV6_ID_OFFSET);
    }

    return 0;
  }

  public static int getInternetProtocolHeaderLength(byte[] packet, int ipStart) {
    // assume the first ext hdr is the fragmentation hdr
    int protocol = packet[ipStart + IPV6_NEXTHEADER_OFFSET];
    if (protocol == IPV6_FRAGMENT_EXTENTION_TYPE) {
      // extension hdr found, add ext hdr size to std hdr size
      return IPV6_HEADER_SIZE + IPV6_FRAGMENT_EXTENTION_SIZE;
    }
    return IPV6_HEADER_SIZE;
  }

  public static int buildInternetProtocolV6ExtensionHeaderFragment(Packet packet, byte[] packetData,
      int ipStart) {
    if (packet.isFragmented()) {
      long id = PcapReaderUtil
          .convertUnsignedInt(packetData, ipStart + IPV6_HEADER_SIZE + IPV6_ID_OFFSET);
      packet.setIpId(id);

      int flags = packetData[ipStart + IPV6_HEADER_SIZE + IPV6_MFLAG_OFFSET] & 0x7;
      packet.setFragmentFlagM((flags & 0x1) == 0);

      long fragmentOffset =
          PcapReaderUtil.convertShort(packetData, ipStart + IPV6_HEADER_SIZE + IPV6_FRAGMENT_OFFSET)
              & 0xFFF8;
      packet.setFragOffset(fragmentOffset);

      packet.setLastFragment(((flags & 0x1) == 0 && fragmentOffset != 0));

      // Change protocol to value from fragment header
      packet.setProtocol(packetData[ipStart + IPV6_HEADER_SIZE]);

      return IPV6_FRAGMENT_EXTENTION_SIZE; // Return fragment header extension length
    }
    // Not a fragment
    return 0;
  }


}
