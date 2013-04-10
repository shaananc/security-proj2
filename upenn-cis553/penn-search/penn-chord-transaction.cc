#include "penn-chord-transaction.h"


using namespace ns3;
using namespace std;

PennChordTransaction::PennChordTransaction (Callback<void ,PennChordMessage::PennChordPacket, Ipv4Address, uint16_t> replyProcFn, uint32_t transactionId, PennChordMessage::PennChordPacket chordPacket, Ptr<remote_node> remoteNode, Time requestTimeout, uint8_t maxRequestRetries)
{
  m_transactionId = transactionId;
  m_chordPacket = chordPacket;
  m_requestTimeout = requestTimeout;
  m_maxRetries = maxRequestRetries;
  m_replyProcFn = replyProcFn;
  m_remoteNode = remoteNode;
  m_requestTimeoutEventId = EventId ();
}

PennChordTransaction::~PennChordTransaction ()
{
}

void
PennChordTransaction::DoDispose ()
{
  Simulator::Cancel (m_requestTimeoutEventId);
}

