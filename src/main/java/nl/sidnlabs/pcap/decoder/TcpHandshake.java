package nl.sidnlabs.pcap.decoder;

import lombok.Data;

@Data
public class TcpHandshake {

  public enum HANDSHAKE_STATE {
    SYN_RECV, SYN_ACK_SENT, ACK_RECV
  }

  private HANDSHAKE_STATE state;
  private long synTs;
  private long ackTs;

  public TcpHandshake() {
    this.state = HANDSHAKE_STATE.SYN_RECV;
  }

  public long rtt() {
    return ackTs - synTs;
  }
}
