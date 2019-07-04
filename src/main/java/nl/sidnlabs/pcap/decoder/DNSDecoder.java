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

import lombok.Data;
import lombok.extern.log4j.Log4j2;
import nl.sidnlabs.dnslib.message.Message;
import nl.sidnlabs.dnslib.message.util.NetworkData;
import nl.sidnlabs.pcap.packet.DNSPacket;
import nl.sidnlabs.pcap.packet.Packet;

/**
 * Decode the dns payload of an UDP or TCP message
 *
 */
@Data
@Log4j2
public class DNSDecoder {

  private int dnsDecodeError;
  private int messageCounter;

  public Packet decode(Packet packet, byte[] payload) {

    DNSPacket dnsPacket = (DNSPacket) packet;
    try {
      dnsPacket.pushMessage(new Message(new NetworkData(payload)));
      messageCounter++;
    } catch (Exception e) {
      if (log.isDebugEnabled()) {
        log.debug("Error decoding, maybe corrupt packet? " + dnsPacket, e);
      }
      dnsDecodeError++;
    }

    return packet;
  }

  public void reset() {
    dnsDecodeError = 0;
    messageCounter = 0;
  }

}
