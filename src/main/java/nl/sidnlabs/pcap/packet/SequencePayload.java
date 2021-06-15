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
import lombok.Setter;
import nl.sidnlabs.pcap.decoder.ChainBuffer;

/**
 * Class for re-assembly of TCP fragments
 * 
 */
@Getter
@Setter
public class SequencePayload implements Comparable<SequencePayload> {
  private Long seq;
  // do not use the actual payload bytes to create string rep and to calc the hash
  // this takes too much cpu resources
  private byte[] bytes;
  // buffer is used to keep bytes that remain after decoding dns data
  // we never want to create new byte[] buffers as this makes things very slow.
  private ChainBuffer buffer;
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

  public boolean hasBuffer() {
    return buffer != null;
  }

  public int size() {
    if (hasBuffer()) {
      return buffer.readableBytes();
    }

    return bytes.length;
  }

  @Override
  public int compareTo(SequencePayload o) {
    return ComparisonChain.start().compare(seq, o.seq).result();
  }

  public boolean linked(SequencePayload o) {
    if (nextSequence == o.seq)
      return true;

    return (o.getNextSequence()) == seq;
  }

  @Override
  public String toString() {
    return "SequencePayload [seq=" + seq + ", time=" + time + ", nextSequence=" + nextSequence
        + ", ignore=" + ignore + "]";
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (ignore ? 1231 : 1237);
    result = prime * result + (int) (nextSequence ^ (nextSequence >>> 32));
    result = prime * result + ((seq == null) ? 0 : seq.hashCode());
    result = prime * result + (int) (time ^ (time >>> 32));
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    SequencePayload other = (SequencePayload) obj;
    if (ignore != other.ignore)
      return false;
    if (nextSequence != other.nextSequence)
      return false;
    if (seq == null) {
      if (other.seq != null)
        return false;
    } else if (!seq.equals(other.seq))
      return false;
    if (time != other.time)
      return false;

    return true;
  }

}
