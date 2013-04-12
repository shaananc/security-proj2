/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/penn-search-message.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("PennSearchMessage");
NS_OBJECT_ENSURE_REGISTERED (PennSearchMessage);

PennSearchMessage::PennSearchMessage ()
{
}

PennSearchMessage::~PennSearchMessage ()
{
}

PennSearchMessage::PennSearchMessage (PennSearchMessage::MessageType messageType, uint32_t transactionId)
{
  m_messageType = messageType;
  m_transactionId = transactionId;
}

TypeId 
PennSearchMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("PennSearchMessage")
    .SetParent<Header> ()
    .AddConstructor<PennSearchMessage> ()
  ;
  return tid;
}

TypeId
PennSearchMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}


uint32_t
PennSearchMessage::GetSerializedSize (void) const
{
  // size of messageType, transaction id
  uint32_t size = sizeof (uint8_t) + sizeof (uint32_t);
  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.GetSerializedSize ();
        break;
      case PING_RSP:
        size += m_message.pingRsp.GetSerializedSize ();
        break;
      case PUBLISH_REQ:
        size += m_message.publishReq.GetSerializedSize ();
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

void
PennSearchMessage::Print (std::ostream &os) const
{
  os << "\n****PennSearchMessage Dump****\n" ;
  os << "messageType: " << m_messageType << "\n";
  os << "transactionId: " << m_transactionId << "\n";
  os << "PAYLOAD:: \n";
  
  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Print (os);
        break;
      case PING_RSP:
        m_message.pingRsp.Print (os);
        break;
      case PUBLISH_REQ:
        m_message.publishReq.Print (os);
        break;
      default:
        break;  
    }
  os << "\n****END OF MESSAGE****\n";
}

void
PennSearchMessage::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (m_messageType);
  i.WriteHtonU32 (m_transactionId);

  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Serialize (i);
        break;
      case PING_RSP:
        m_message.pingRsp.Serialize (i);
        break;
      case PUBLISH_REQ:
        m_message.publishReq.Serialize (i);
        break;
      default:
        NS_ASSERT (false);   
    }
}

uint32_t 
PennSearchMessage::Deserialize (Buffer::Iterator start)
{
  uint32_t size;
  Buffer::Iterator i = start;
  m_messageType = (MessageType) i.ReadU8 ();
  m_transactionId = i.ReadNtohU32 ();

  size = sizeof (uint8_t) + sizeof (uint32_t);

  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.Deserialize (i);
        break;
      case PING_RSP:
        size += m_message.pingRsp.Deserialize (i);
        break;
      case PUBLISH_REQ:
        size += m_message.publishReq.Deserialize (i);
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t 
PennSearchMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
PennSearchMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
PennSearchMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennSearchMessage::PingReq::Deserialize (Buffer::Iterator &start)
{  
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingReq::GetSerializedSize ();
}

void
PennSearchMessage::SetPingReq (std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_REQ);
    }
  m_message.pingReq.pingMessage = pingMessage;
}

PennSearchMessage::PingReq
PennSearchMessage::GetPingReq ()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t 
PennSearchMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}



void
PennSearchMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
PennSearchMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennSearchMessage::PingRsp::Deserialize (Buffer::Iterator &start)
{  
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingRsp::GetSerializedSize ();
}


void
PennSearchMessage::SetPingRsp (std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_RSP);
    }
  m_message.pingRsp.pingMessage = pingMessage;
}

PennSearchMessage::PingRsp
PennSearchMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}

void
PennSearchMessage::PublishReq::Print (std::ostream &os) const
{
  for(std::map<std::string, std::vector<std::string> >::const_iterator it=publishMessage.begin(); it!=publishMessage.end(); it++){   
    os << "PublishReq:: Key: " << it->first << "\n";
    for(std::vector<std::string>::const_iterator iter=(it->second).begin(); iter!=(it->second).end(); it++){
        os << "PublishReq:: Docs: " << (*iter) << "\n";
    }
  }
}

void
PennSearchMessage::PublishReq::Serialize (Buffer::Iterator &start) const
{
  //Input the size of the map first for ease of deserialization
  start.WriteU16 (publishMessage.size());

  for(std::map<std::string, std::vector<std::string> >::const_iterator it=publishMessage.begin(); it!=publishMessage.end(); it++){
        start.WriteU16 (it->first.length());
        start.Write ((uint8_t *) ((char*) (it->first.c_str())), it->first.length());
        
        //Save the size of the vector of docs for ease of deserialization
        start.WriteU16 (it->second.size());

        for(std::vector<std::string>::const_iterator iter=it->second.begin(); iter!=it->second.end(); iter++){
            start.WriteU16 ((*iter).length());
            start.Write ((uint8_t *) ((char*) ((*iter).c_str())), (*iter).length());
        }
  }


}

uint32_t
PennSearchMessage::PublishReq::Deserialize (Buffer::Iterator &start)
{  
  std::vector<std::string> documents;
  uint16_t size = start.ReadU16 ();
  for(int s=0; s<size; s++){
        uint16_t length1 = start.ReadU16 ();
        char* str = (char*) malloc (length1);
        start.Read ((uint8_t*)str, length1);
        uint16_t size2 = start.ReadU16 ();
        for(int j=0; j<size2; j++){
            uint16_t length2 = start.ReadU16 ();
            char* doc = (char*) malloc (length2);
            start.Read ((uint8_t*)doc, length2);
            documents.push_back(doc);
        }
        publishMessage.insert(std::make_pair(str, documents));
        free(str);
        documents.clear();
  }

  return PublishReq::GetSerializedSize ();

}

uint32_t 
PennSearchMessage::PublishReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + publishMessage.size();
  for(std::map<std::string, std::vector<std::string> >::const_iterator it=publishMessage.begin(); it!=publishMessage.end(); it++){
        size = size + it->first.length() + it->second.size();
        for(std::vector<std::string>::const_iterator iter=it->second.begin(); iter!=it->second.end(); iter++){
            size = size + (*iter).length();
        }
  }
  return size;
}



PennSearchMessage::PublishReq
PennSearchMessage::GetPublishReq ()
{
  return m_message.publishReq;
}

void PennSearchMessage::SetPublishReq (std::map<std::string, std::vector<std::string> > &publishMessage)
{
    if(m_messageType == 0){
        m_messageType = PUBLISH_REQ;
    }
    else{
        NS_ASSERT (m_messageType == PUBLISH_REQ);
    }
    std::map<std::string, std::vector<std::string> >::iterator it;
    for(it = publishMessage.begin(); it!=publishMessage.end(); it++){
        m_message.publishReq.publishMessage.insert(std::make_pair(it->first, it->second));   
    }
}


//
//
//

void
PennSearchMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

PennSearchMessage::MessageType
PennSearchMessage::GetMessageType () const
{
  return m_messageType;
}

void
PennSearchMessage::SetTransactionId (uint32_t transactionId)
{
  m_transactionId = transactionId;
}

uint32_t 
PennSearchMessage::GetTransactionId (void) const
{
  return m_transactionId;
}

