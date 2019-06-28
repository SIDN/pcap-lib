package nl.sidnlabs.pcap.packet;

import lombok.Data;

@Data
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

  public long rtt() {
    return ackTs - synTs;
  }
}
