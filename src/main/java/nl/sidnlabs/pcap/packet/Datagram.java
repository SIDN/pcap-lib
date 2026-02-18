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
    if (this == o) {
      return 0;
    }

    int c = compareNullable(src, o.src);
    if (c != 0) {
      return c;
    }

    c = compareNullable(dst, o.dst);
    if (c != 0) {
      return c;
    }

    c = compareNullable(id, o.id);
    if (c != 0) {
      return c;
    }

    return compareNullable(protocol, o.protocol);
  }

  private static <T extends Comparable<? super T>> int compareNullable(T a, T b) {
    if (a == b) {
      return 0;
    }
    if (a == null) {
      return 1; // nullsLast
    }
    if (b == null) {
      return -1; // nullsLast
    }
    return a.compareTo(b);
  }



}
