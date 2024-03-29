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

#ifndef PENN_SEARCH_MESSAGE_H
#define PENN_SEARCH_MESSAGE_H

#include <vector>
#include <map>
#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/packet.h"
#include "ns3/object.h"
//#include "ns3/penn-search.h"
#include "ns3/SearchRes.h"

using namespace ns3;

#define IPV4_ADDRESS_SIZE 4

class PennSearchMessage : public Header {
public:
    PennSearchMessage();
    virtual ~PennSearchMessage();

    enum MessageType {
        PING_REQ = 1,
        PING_RSP = 2,
        // Define extra message types when needed 
        PUBLISH_REQ = 3,
        PUBLISH_RSP = 4,
        SEARCH_INIT = 5,
        SEARCH_RES = 6,
        SEARCH_FIN = 7,
      };

    PennSearchMessage(PennSearchMessage::MessageType messageType, uint32_t transactionId);

    /**
     *  \brief Sets message type
     *  \param messageType message type
     */
    void SetMessageType(MessageType messageType);

    /**
     *  \returns message type
     */
    MessageType GetMessageType() const;

    /**
     *  \brief Sets Transaction Id
     *  \param transactionId Transaction Id of the request
     */
    void SetTransactionId(uint32_t transactionId);

    /**
     *  \returns Transaction Id
     */
    uint32_t GetTransactionId() const;

private:
    /**
     *  \cond
     */
    MessageType m_messageType;
    uint32_t m_transactionId;
    /**
     *  \endcond
     */
public:
    static TypeId GetTypeId(void);
    virtual TypeId GetInstanceTypeId(void) const;
    void Print(std::ostream &os) const;
    uint32_t GetSerializedSize(void) const;
    void Serialize(Buffer::Iterator start) const;
    uint32_t Deserialize(Buffer::Iterator start);

    struct PingReq {
        void Print(std::ostream &os) const;
        uint32_t GetSerializedSize(void) const;
        void Serialize(Buffer::Iterator &start) const;
        uint32_t Deserialize(Buffer::Iterator &start);
        // Payload
        std::string pingMessage;
    };

    struct PingRsp {
        void Print(std::ostream &os) const;
        uint32_t GetSerializedSize(void) const;
        void Serialize(Buffer::Iterator &start) const;
        uint32_t Deserialize(Buffer::Iterator &start);
        // Payload
        std::string pingMessage;
      };

 struct PublishRsp {
        void Print(std::ostream &os) const;
        uint32_t GetSerializedSize(void) const;
        void Serialize(Buffer::Iterator &start) const;
        uint32_t Deserialize(Buffer::Iterator &start);
        std::map<std::string, std::vector<std::string> > publishMessage;
    };

    struct PublishReq {
        void Print(std::ostream &os) const;
        uint32_t GetSerializedSize(void) const;
        void Serialize(Buffer::Iterator &start) const;
        uint32_t Deserialize(Buffer::Iterator &start);
    };

    struct SearchInit
    {

        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
      //Check this - should be type of struct
        SearchRes searchMessage;
    };

    struct SearchRsp
    {

        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
      //Check this
        SearchRes searchMessage;
    };

    struct SearchFin
    {

        void Print (std::ostream &os) const;
        uint32_t GetSerializedSize (void) const;
        void Serialize (Buffer::Iterator &start) const;
        uint32_t Deserialize (Buffer::Iterator &start);
        SearchRes searchMessage;
    };

  private:
    struct
      {
        PingReq pingReq;
        PingRsp pingRsp;
        PublishRsp publishRsp;
        PublishReq publishReq;
        SearchInit searchInit;
        SearchRsp searchRes;
        SearchFin searchFin;
      } m_message;
    
  public:
    /**
     *  \returns PingReq Struct
     */
    PingReq GetPingReq();

    /**
     *  \brief Sets PingReq message params
     *  \param message Payload String
     */

    void SetPingReq(std::string message);

    /**
     * \returns PingRsp Struct
     */
    PingRsp GetPingRsp();
    /**
     *  \brief Sets PingRsp message params
     *  \param message Payload String
     */
    void SetPingRsp(std::string message);

    //Returns publishRsp Struct
    PublishRsp GetPublishRsp();

    //Set the message
    void SetPublishRsp(std::map<std::string, std::vector<std::string> > &message);

    //Returns searchInit Struct
    SearchInit GetSearchInit ();

    //Set the message
    void SetSearchInit (SearchRes &message);

    //Returns searchRes Struct
    SearchRsp GetSearchRsp ();

    //Set the message
    void SetSearchRsp (SearchRes &message);

    //Returns searchFin Struct
    SearchFin GetSearchFin ();

    //Set the message
    void SetSearchFin (SearchRes &message);


}; // class PennSearchMessage

static inline std::ostream& operator<<(std::ostream& os, const PennSearchMessage& message) {
    message.Print(os);
    return os;
}

#endif
