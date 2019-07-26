package nl.sidnlabs.pcap;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.Data;
import lombok.extern.log4j.Log4j2;

@Log4j2
@Data
public class FlowData {

  private int nextDnsMsgLen;
  private int bytesAvail;

  private long lastSequence;

  // add all payloads to a set, this should prevent issues when there are
  // duplicates caused by retransmissions
  private Set<SequencePayload> payloads = new HashSet<>();

  /**
   * Add new SequencePayload to the list of sequences, if the sequece is out-of-order then it will
   * not be added to the list
   * 
   * @param p sequence
   * @return true if the sequence has been added
   */
  public boolean addPayload(SequencePayload p) {
    if (p.getSeq().longValue() > lastSequence) {
      payloads.add(p);
      lastSequence = p.getSeq().longValue();
      return true;
    }

    log.warn("Received out-of-order sequence, ignoring: {}", p);
    return false;
  }

  public int size() {
    return payloads.size();
  }

  public List<SequencePayload> getSortedPayloads() {
    return payloads.stream().sorted().collect(Collectors.toList());
  }

  public boolean isNextPayloadAvail() {
    // check if we have enough bytes received for the next dns message
    // add 2 bytes for the dns msg size prefix
    return bytesAvail >= (nextDnsMsgLen + 2);
  }

}
