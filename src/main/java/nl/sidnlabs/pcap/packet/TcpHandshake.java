package nl.sidnlabs.pcap.packet;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Getter
@Setter
public class TcpHandshake {

  public enum HANDSHAKE_STATE {
    SYN_RECV, SYN_ACK_SENT, ACK_RECV
  }

  private HANDSHAKE_STATE state;
  private long synTs;
  private long ackTs;

  private long clientSynSeq;
  private long serverSynSeq;
  private long serverAckSeq;
  private long clientAckSeq;

  public TcpHandshake(long clientSynSeq) {
    this.state = HANDSHAKE_STATE.SYN_RECV;
    this.clientSynSeq = clientSynSeq;
  }

  public int rtt() {
    return (int) (ackTs - synTs);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (int) (ackTs ^ (ackTs >>> 32));
    result = prime * result + (int) (clientAckSeq ^ (clientAckSeq >>> 32));
    result = prime * result + (int) (clientSynSeq ^ (clientSynSeq >>> 32));
    result = prime * result + (int) (serverAckSeq ^ (serverAckSeq >>> 32));
    result = prime * result + (int) (serverSynSeq ^ (serverSynSeq >>> 32));
    result = prime * result + ((state == null) ? 0 : state.hashCode());
    result = prime * result + (int) (synTs ^ (synTs >>> 32));
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
    TcpHandshake other = (TcpHandshake) obj;
    if (ackTs != other.ackTs)
      return false;
    if (clientAckSeq != other.clientAckSeq)
      return false;
    if (clientSynSeq != other.clientSynSeq)
      return false;
    if (serverAckSeq != other.serverAckSeq)
      return false;
    if (serverSynSeq != other.serverSynSeq)
      return false;
    if (state != other.state)
      return false;
    if (synTs != other.synTs)
      return false;
    return true;
  }


}
