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


import com.google.common.collect.ComparisonChain;
import lombok.Getter;

@Getter
public class DatagramPayload implements Comparable<DatagramPayload> {
  private long offset;
  private byte[] payload;


  /** no-arg constructor for Kryo **/
  public DatagramPayload() {}

  public DatagramPayload(long offset, byte[] payload) {
    this.offset = offset;
    this.payload = payload;
  }

  @Override
  public int compareTo(DatagramPayload o) {
    return ComparisonChain
        .start()
        .compare(offset, o.offset)
        .compare(payload.length, o.payload.length)
        .result();
  }

  public boolean linked(DatagramPayload o) {
    if ((offset + payload.length) == o.offset)
      return true;

    return (o.offset + o.payload.length) == offset;
  }

}
