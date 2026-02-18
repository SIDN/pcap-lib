package nl.sidnlabs.pcap;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.List;
import nl.sidnlabs.pcap.packet.Packet;
import org.junit.jupiter.api.Test;

class PcapReaderTest {

  @Test
  void readsSingleIpv4IcmpPacket_littleEndianPcap() throws Exception {
    byte[] pcapBytes = buildPcapWithSingleIpv4IcmpEcho(false);

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(pcapBytes))) {
      PcapReader reader = new PcapReader(dis, false);
      List<Packet> packets = reader.stream().toList();

      assertEquals(1, packets.size());
      Packet p = packets.get(0);
      assertNotNull(p);
      assertFalse(p == Packet.NULL);

      assertEquals(4, p.getIpVersion());
      assertEquals(1, p.getProtocol());
      assertEquals(64, p.getTtl());
      assertEquals("1.2.3.4", p.getSrc());
      assertEquals("5.6.7.8", p.getDst());
      assertEquals(28, p.getTotalLength());
    }
  }

  @Test
  void readsSingleIpv4IcmpPacket_reversedEndianPcap() throws Exception {
    byte[] pcapBytes = buildPcapWithSingleIpv4IcmpEcho(true);

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(pcapBytes))) {
      PcapReader reader = new PcapReader(dis, false);
      List<Packet> packets = reader.stream().toList();

      assertEquals(1, packets.size());
      Packet p = packets.get(0);
      assertNotNull(p);
      assertFalse(p == Packet.NULL);

      assertEquals(4, p.getIpVersion());
      assertEquals(1, p.getProtocol());
      assertEquals("1.2.3.4", p.getSrc());
      assertEquals("5.6.7.8", p.getDst());
    }
  }

  @Test
  void emptyFileDoesNotThrowInConstructor() {
    assertDoesNotThrow(
        () -> {
          try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(new byte[0]))) {
            new PcapReader(dis, false);
          }
        });
  }

  private static byte[] buildPcapWithSingleIpv4IcmpEcho(boolean reversedEndianHeader)
      throws IOException {
    byte[] packetData = buildEthernetIpv4IcmpPacket();

    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // PCAP global header (24 bytes)
    byte[] hdr = new byte[24];
    if (!reversedEndianHeader) {
      // little-endian magic: d4 c3 b2 a1
      hdr[0] = (byte) 0xD4;
      hdr[1] = (byte) 0xC3;
      hdr[2] = (byte) 0xB2;
      hdr[3] = (byte) 0xA1;
      // linktype at offset 20: 1 (EN10MB), little-endian
      writeIntLE(hdr, 20, 1);
    } else {
      // big-endian magic: a1 b2 c3 d4 (forces reverseHeaderByteOrder=true)
      hdr[0] = (byte) 0xA1;
      hdr[1] = (byte) 0xB2;
      hdr[2] = (byte) 0xC3;
      hdr[3] = (byte) 0xD4;
      // linktype at offset 20: 1 (EN10MB), big-endian
      writeIntBE(hdr, 20, 1);
    }
    out.write(hdr);

    // Packet header (16 bytes)
    byte[] ph = new byte[16];
    if (!reversedEndianHeader) {
      writeIntLE(ph, 0, 0); // ts_sec
      writeIntLE(ph, 4, 0); // ts_usec
      writeIntLE(ph, 8, packetData.length); // incl_len
      writeIntLE(ph, 12, packetData.length); // orig_len
    } else {
      writeIntBE(ph, 0, 0);
      writeIntBE(ph, 4, 0);
      writeIntBE(ph, 8, packetData.length);
      writeIntBE(ph, 12, packetData.length);
    }
    out.write(ph);
    out.write(packetData);

    return out.toByteArray();
  }

  private static byte[] buildEthernetIpv4IcmpPacket() {
    // Ethernet(14) + IPv4(20) + ICMP(8)
    byte[] packet = new byte[14 + 20 + 8];

    // dest MAC (6) + src MAC (6) left as zeros
    // EtherType: IPv4 (0x0800) at bytes 12-13 (big-endian network order)
    packet[12] = 0x08;
    packet[13] = 0x00;

    int ipStart = 14;

    // IPv4 header
    packet[ipStart] = 0x45; // version=4, IHL=5
    packet[ipStart + 1] = 0x00;
    // total length 28 bytes
    packet[ipStart + 2] = 0x00;
    packet[ipStart + 3] = 0x1C;
    // identification
    packet[ipStart + 4] = 0x00;
    packet[ipStart + 5] = 0x00;
    // flags/fragment offset
    packet[ipStart + 6] = 0x00;
    packet[ipStart + 7] = 0x00;
    // TTL
    packet[ipStart + 8] = 64;
    // protocol: ICMP
    packet[ipStart + 9] = 1;
    // checksum (ignored)
    packet[ipStart + 10] = 0x00;
    packet[ipStart + 11] = 0x00;
    // src ip 1.2.3.4
    packet[ipStart + 12] = 1;
    packet[ipStart + 13] = 2;
    packet[ipStart + 14] = 3;
    packet[ipStart + 15] = 4;
    // dst ip 5.6.7.8
    packet[ipStart + 16] = 5;
    packet[ipStart + 17] = 6;
    packet[ipStart + 18] = 7;
    packet[ipStart + 19] = 8;

    // ICMP echo request
    int icmpStart = ipStart + 20;
    packet[icmpStart] = 8; // type
    packet[icmpStart + 1] = 0; // code
    packet[icmpStart + 2] = 0; // checksum
    packet[icmpStart + 3] = 0;
    packet[icmpStart + 4] = 0; // identifier
    packet[icmpStart + 5] = 0;
    packet[icmpStart + 6] = 0; // sequence
    packet[icmpStart + 7] = 0;

    return packet;
  }

  private static void writeIntLE(byte[] buf, int offset, int value) {
    buf[offset] = (byte) (value & 0xFF);
    buf[offset + 1] = (byte) ((value >>> 8) & 0xFF);
    buf[offset + 2] = (byte) ((value >>> 16) & 0xFF);
    buf[offset + 3] = (byte) ((value >>> 24) & 0xFF);
  }

  private static void writeIntBE(byte[] buf, int offset, int value) {
    buf[offset] = (byte) ((value >>> 24) & 0xFF);
    buf[offset + 1] = (byte) ((value >>> 16) & 0xFF);
    buf[offset + 2] = (byte) ((value >>> 8) & 0xFF);
    buf[offset + 3] = (byte) (value & 0xFF);
  }
}
