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

import com.google.common.collect.ComparisonChain;
import lombok.Data;
import lombok.ToString;
import nl.sidnlabs.pcap.packet.TCPFlow;

/**
 * Class for re-assembly of TCP fragments
 * 
 */
@Data
public class SequencePayload implements Comparable<SequencePayload> {
  private Long seq;
  @ToString.Exclude
  private byte[] bytes;
  private long time;
  private long nextSequence;
  // ignore = true when payload is received out of order
  private boolean ignore;

  public SequencePayload() {}

  public SequencePayload(Long seq, byte[] bytes, long time, TCPFlow flow) {
    this.seq = seq;
    this.bytes = bytes;
    this.time = time;
    this.nextSequence = seq + bytes.length;
  }

  @Override
  public int compareTo(SequencePayload o) {
    return ComparisonChain
        .start()
        .compare(seq, o.seq)
        .compare(bytes.length, o.bytes.length)
        .result();
  }

  public boolean linked(SequencePayload o) {
    if (nextSequence == o.seq)
      return true;

    return (o.getNextSequence()) == seq;
  }

}
