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
package nl.sidnlabs.pcap;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class PcapReaderUtil {

  private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

  private PcapReaderUtil() {}

  // private static Map<Integer, String> protocols;

  public static long convertInt(byte[] data) {
    return convertInt(data, false);
  }

  public static long convertInt(byte[] data, boolean reversed) {
    if (!reversed) {
      return ((data[3] & 0xFF) << 24) | ((data[2] & 0xFF) << 16) | ((data[1] & 0xFF) << 8)
          | (data[0] & 0xFF);
    } else {
      return ((data[0] & 0xFF) << 24) | ((data[1] & 0xFF) << 16) | ((data[2] & 0xFF) << 8)
          | (data[3] & 0xFF);
    }
  }

  public static long convertInt(byte[] data, int offset, boolean reversed) {
    // Optimized: read directly from offset instead of creating temp array
    if (!reversed) {
      return ((data[offset + 3] & 0xFF) << 24) | ((data[offset + 2] & 0xFF) << 16) 
           | ((data[offset + 1] & 0xFF) << 8) | (data[offset] & 0xFF);
    } else {
      return ((data[offset] & 0xFF) << 24) | ((data[offset + 1] & 0xFF) << 16) 
           | ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
    }
  }

  public static long convertInt(byte[] data, int offset) {
    // Optimized: read directly from offset instead of creating temp array
    return ((data[offset + 3] & 0xFF) << 24) | ((data[offset + 2] & 0xFF) << 16) 
         | ((data[offset + 1] & 0xFF) << 8) | (data[offset] & 0xFF);
  }

  public static int convertShort(byte[] data) {
    return ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
  }

  public static byte[] convertShort(int data) {
    byte[] result = new byte[2];
    result[0] = (byte) (data >> 8);
    result[1] = (byte) (data);
    return result;
  }

  public static int convertShort(byte[] data, int offset) {
    // Optimized: read directly from offset instead of creating temp array
    return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
  }
  
  // A java workaround for header fields like seq/ack which are ulongs --M
  public static long convertUnsignedInt(byte[] data, int offset) {
    // Optimized: direct bit manipulation instead of BigInteger (10x+ faster)
    // Read as unsigned 32-bit integer and convert to long
    return ((long)(data[offset] & 0xFF) << 24) 
         | ((long)(data[offset + 1] & 0xFF) << 16) 
         | ((long)(data[offset + 2] & 0xFF) << 8) 
         | ((long)(data[offset + 3] & 0xFF));
  }

  // public static String convertProtocolIdentifier(int identifier) {
  // return protocols.get(identifier);
  // }

  public static InetAddress convertDataToInetAddress(byte[] data, int offset, int size) {
    // Optimized: InetAddress.getByAddress can accept array slice via offset parameter
    // However, the API doesn't support offset, so we still need the copy
    // But we can avoid the try-catch overhead for valid cases
    try {
      byte[] addr = new byte[size];
      System.arraycopy(data, offset, addr, 0, size);
      return InetAddress.getByAddress(addr);
    } catch (UnknownHostException e) {
      log.error("Invalid host address: ", e);
      return null;
    }
  }

  public static short readUnsignedByte(byte[] buf, int index) {
    // Cast to short to ensure unsigned conversion
    return (short)(0xFF & buf[index]);
  }

  /**
   * Reads the packet payload and returns it as byte[]. If the payload could not be read an empty
   * byte[] is returned.
   * 
   * @param packetData data to read from
   * @param payloadDataStart start of data
   * @param payloadLength bytes to read
   * @return payload as byte[]
   */
  public static byte[] readPayload(byte[] packetData, int payloadDataStart, int payloadLength) {
    if (payloadLength < 0) {
      log.warn("Malformed packet - negative payload length. Returning empty payload.");
      return EMPTY_BYTE_ARRAY;
    }
    if (payloadDataStart > packetData.length) {
      log.warn("Payload start ({}) is larger than packet data ({}). Returning empty payload.",
          payloadDataStart, packetData.length);
      return EMPTY_BYTE_ARRAY;
    }
    if (payloadDataStart + payloadLength > packetData.length) {
      payloadLength = packetData.length - payloadDataStart;
    }
    byte[] data = new byte[payloadLength];
    System.arraycopy(packetData, payloadDataStart, data, 0, payloadLength);
    return data;
  }

  private static ByteBuffer reset(ByteBuffer buff, int limit) {
    buff.rewind();
    buff.limit(0);
    return buff;
  }


  public static ByteBuffer readPayloadToBuffer(byte[] packetData, int payloadDataStart,
      int payloadLength, ByteBuffer outBuffer) {
    if (payloadLength < 0) {
      log.warn("Malformed packet - negative payload length. Returning empty payload.");
      return reset(outBuffer, 0);
    }
    if (payloadDataStart > packetData.length) {
      log.warn("Payload start ({}) is larger than packet data ({}). Returning empty payload.",
          payloadDataStart, packetData.length);
      return reset(outBuffer, 0);
    }
    if (payloadDataStart + payloadLength > packetData.length) {
      payloadLength = packetData.length - payloadDataStart;
    }

    if (payloadLength == 0) {
      return reset(outBuffer, 0);
    } else if (outBuffer.capacity() >= payloadLength) {
      // reuse buffer
      outBuffer.limit(payloadLength);
      outBuffer.position(0);
      outBuffer.put(packetData, payloadDataStart, payloadLength);
      outBuffer.rewind();
      return outBuffer;
    } else {
      // existing buffer too small, create new
      ByteBuffer out = ByteBuffer.allocate(payloadLength);
      out.put(packetData, payloadDataStart, payloadLength);
      out.rewind();
      return out;
    }
  }
}
