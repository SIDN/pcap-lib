package nl.sidnlabs.pcap.packet;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FlowData {

  private long lastSequence;
  private long lastSize;

  // add all payloads to a set, this should prevent issues when there are
  // duplicates caused by retransmissions
  private Set<SequencePayload> payloads = new HashSet<>();

  /**
   * Add new SequencePayload to the list of sequences, if the sequence is out-of-order then it will
   * not be added to the list
   * 
   * @param p SequencePayload
   */
  public void addPayload(SequencePayload p) {
    payloads.add(p);
    lastSequence = p.getSeq();
    // do not update the lastSize when adding partial data
    // otherwise matching retransmission based on next expected seq will fail
    lastSize = p.size();
  }


  public int size() {
    return payloads.size();
  }

  public List<SequencePayload> getSortedPayloads() {
    return payloads.stream().sorted().collect(Collectors.toList());
  }

  public List<SequencePayload> getPayloads() {
    return payloads.stream().collect(Collectors.toList());
  }

  public boolean isMinPayloadAvail() {
    // check if we have enough bytes received for the next dns message
    // add 2 bytes for the dns msg size prefix

    for (SequencePayload p : payloads) {
      if (p.size() > 2) {
        return true;
      }
    }

    return false;

  }

  public long getNextExpectedSequence() {
    return lastSequence + lastSize;
  }

  public int getBytesAvail() {
    int sum = 0;
    for (SequencePayload p : payloads) {
      sum += p.size();
    }

    return sum;
  }

}
