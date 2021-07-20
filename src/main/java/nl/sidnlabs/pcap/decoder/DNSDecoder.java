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

import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;
import nl.sidnlabs.dnslib.message.Message;
import nl.sidnlabs.dnslib.message.util.NetworkData;
import nl.sidnlabs.pcap.packet.DNSPacket;
import nl.sidnlabs.pcap.packet.Packet;

/**
 * Decode the dns payload of an UDP or TCP message
 *
 */
@Getter
@Setter
@Log4j2
public class DNSDecoder {

  // if true then ignore any error, this can happen when decoding
  // partial dns messages that are the payload in ICMP packets.
  private boolean allowFail;
  private int messageDecodeError;
  private int messageCounter;

  // reuse network data instance
  private NetworkData networkData;

  public DNSDecoder(boolean allowFail) {
    this.allowFail = allowFail;
  }

  /**
   * Decode byte[] into a DNS packet
   * 
   * @param packet the packet that contains all decoded data
   * @param payload byte[] with raw data to decode
   * @param offset the offset in the payload to start decoding
   * @param length the number of bytes to decode
   * @return
   */
  public Packet decode(Packet packet, byte[] payload, int offset, int length) {

    DNSPacket dnsPacket = (DNSPacket) packet;
    try {
      // decode the message use partial == true
      // this will save of lot of objects from getting created
      // and this results in less garbage collection delays
      if (networkData == null) {
        networkData = new NetworkData(payload, offset, length);
      } else {
        // reuse existing data object, no need to allocate new memory
        networkData.update(payload, offset, length);
      }
      dnsPacket.pushMessage(new Message(networkData, true, allowFail));
      messageCounter++;
    } catch (Exception e) {
      if (!allowFail) {
        if (log.isDebugEnabled()) {
          log.debug("Error decoding, maybe corrupt packet? " + dnsPacket, e);
        }
        messageDecodeError++;
      }
    }

    return packet;
  }

  public void reset() {
    messageDecodeError = 0;
    messageCounter = 0;
  }

  public void printStats() {
    log.info("---------------- DNS decoder stats -----------------------");
    log.info("Messages: {}", Integer.valueOf(messageCounter));
    log.info("Errors: {}", Integer.valueOf(messageDecodeError));
  }

}
