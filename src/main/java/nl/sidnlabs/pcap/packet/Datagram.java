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
import com.google.common.collect.Ordering;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Datagram implements Comparable<Datagram> {
  private String src;
  private String dst;
  private Long id;
  private String protocol;
  private long time;

  /** no-arg constructor for Kryo **/
  public Datagram() {}

  public Datagram(String src, String dst, Long id, String protocol, long time) {
    this.src = src;
    this.dst = dst;
    this.id = id;
    this.protocol = protocol;
    this.time = time;
  }

  @Override
  public int compareTo(Datagram o) {

    return ComparisonChain
        .start()
        .compare(src, o.src, Ordering.natural().nullsLast())
        .compare(dst, o.dst, Ordering.natural().nullsLast())
        .compare(id, o.id, Ordering.natural().nullsLast())
        .compare(protocol, o.protocol, Ordering.natural().nullsLast())
        .result();
  }



}
