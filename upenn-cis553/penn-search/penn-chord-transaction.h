#ifndef PENN_CHORD_TRANSACTION_H
#define PENN_CHORD_TRANSACTION_H

#include <vector>
#include "ns3/object.h"
#include "ns3/nstime.h"
#include "ns3/timer.h"
#include "ns3/penn-chord-message.h"
#include "ns3/remote_node.h"


using namespace ns3;

class PennChordTransaction : public SimpleRefCount<PennChordTransaction>
{
public:
  enum TransactionType
  {
    APPLICATION = 1,
    CHORD = 2,
  };

  /**
   *  \param replyProcFn: The function which is invoked upon receiving reply
   *  \param transactionId: TransactionId to identify the transaction
   *  \param chordPacket: Packet to retransmit in case of timeout
   *  \param remoteNode: Node with which the transaction is
   *  \param requestTimeout: Time to wait before retransmitting
   *  \param maxRequestRetries: Maximum  retries before giving up
   */
  PennChordTransaction (Callback<void ,PennChordMessage::PennChordPacket, Ipv4Address, uint16_t> replyProcFn, uint32_t transactionId, PennChordMessage::PennChordPacket chordPacket, Ptr<remote_node> remoteNode, Time requestTimeout, uint8_t maxRequestRetries);
  virtual ~PennChordTransaction ();
  virtual void DoDispose ();

  Time  m_requestTimeout;
  EventId m_requestTimeoutEventId;
  uint32_t m_transactionId;
  uint8_t m_retries;
  uint8_t m_maxRetries;
  Ptr<remote_node> m_remoteNode;
  Callback<void ,PennChordMessage::PennChordPacket, Ipv4Address, uint16_t> m_replyProcFn;
  // chord packet for retransmissions
  PennChordMessage::PennChordPacket m_chordPacket;
  // Originator type of this transaction
  PennChordTransaction::TransactionType m_transactionType;
};


#endif // PENN_CHORD_TRANSACTION_H
