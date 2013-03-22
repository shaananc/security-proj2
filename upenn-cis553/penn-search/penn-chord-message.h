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

#ifndef PENN_CHORD_MESSAGE_H
#define PENN_CHORD_MESSAGE_H

#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/packet.h"
#include "ns3/object.h"

using namespace ns3;

#define IPV4_ADDRESS_SIZE 4

class PennChordMessage : public Header {
public:
    PennChordMessage();
    virtual ~PennChordMessage();

    enum MessageType {
        PING_REQ = 1,
        PING_RSP = 2,
        CHOR_PAC = 3,
        // Define extra message types when needed       
    };

    PennChordMessage(PennChordMessage::MessageType messageType, uint32_t transactionId);

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

    struct PennChordPacket {

        enum Chord_Type {
            RSP_INF,
            RSP_BOOL,
            REQ_LOC,
            REQ_SUC,
            REQ_CP,
            REQ_NOT,
            REQ_JOIN,
        };



    public:
        virtual void Print(std::ostream &os) const;
        virtual uint32_t GetSerializedSize(void) const;
        virtual void Serialize(Buffer::Iterator start)const;
        virtual uint32_t Deserialize(Buffer::Iterator start);

        Chord_Type m_messageType;
        uint32_t m_transactionId;
        // of whom was the data requested
        Ipv4Address requestee;
        // from whom did the request originate
        Ipv4Address originator;


    };


private:

    struct {
        PingReq pingReq;
        PingRsp pingRsp;
        PennChordPacket chordPacket;
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


    void SetChordPacket(PennChordPacket p);


}; // class PennChordMessage

static inline std::ostream& operator<<(std::ostream& os, const PennChordMessage& message) {
    message.Print(os);
    return os;
}

#endif
