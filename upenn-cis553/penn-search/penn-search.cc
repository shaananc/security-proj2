/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 University of Pennsylvania
 *
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

#include <iostream>
#include <vector>
#include <map>
#include <fstream>
#include <string>
#include <cstdio>
#include "penn-search.h"
#include <openssl/sha.h>

#include "ns3/random-variable.h"
#include "ns3/inet-socket-address.h"
#include "penn-chord.h"

#include <openssl/sha.h>

using namespace ns3;

extern bool inLookup;

TypeId
PennSearch::GetTypeId() {
    static TypeId tid = TypeId("PennSearch")
            .SetParent<PennApplication> ()
            .AddConstructor<PennSearch> ()
            .AddAttribute("AppPort",
            "Listening port for Application",
            UintegerValue(10278),
            MakeUintegerAccessor(&PennSearch::m_appPort),
            MakeUintegerChecker<uint16_t> ())
            .AddAttribute("ChordPort",
            "Listening port for Application",
            UintegerValue(10001),
            MakeUintegerAccessor(&PennSearch::m_chordPort),
            MakeUintegerChecker<uint16_t> ())
            .AddAttribute("PingTimeout",
            "Timeout value for PING_REQ in milliseconds",
            TimeValue(MilliSeconds(2000)),
            MakeTimeAccessor(&PennSearch::m_pingTimeout),
            MakeTimeChecker())
            ;
    return tid;
}

PennSearch::PennSearch()
: m_auditPingsTimer(Timer::CANCEL_ON_DESTROY) {
    m_chord = NULL;
    RandomVariable random;
    SeedManager::SetSeed(time(NULL));
    random = UniformVariable(0x00000000, 0xFFFFFFFF);
    m_currentTransactionId = random.GetInteger();
}

PennSearch::~PennSearch() {

}

void
PennSearch::DoDispose() {
    StopApplication();
    PennApplication::DoDispose();
}

void
PennSearch::StartApplication(void) {
    // Create and Configure PennChord
    ObjectFactory factory;
    factory.SetTypeId(PennChord::GetTypeId());
    factory.Set("AppPort", UintegerValue(m_chordPort));
    m_chord = factory.Create<PennChord> ();
    m_chord->SetNode(GetNode());
    m_chord->SetNodeAddressMap(m_nodeAddressMap);
    m_chord->SetAddressNodeMap(m_addressNodeMap);
    m_chord->SetModuleName("CHORD");
    std::string nodeId = GetNodeId();
    m_chord->SetNodeId(nodeId);
    m_chord->SetLocalAddress(m_local);

    if (PennApplication::IsRealStack()) {
        m_chord->SetRealStack(true);
    }

    // Configure Callbacks with Chord
    m_chord->SetPingSuccessCallback(MakeCallback(&PennSearch::HandleChordPingSuccess, this));
    m_chord->SetPingFailureCallback(MakeCallback(&PennSearch::HandleChordPingFailure, this));
    m_chord->SetPingRecvCallback(MakeCallback(&PennSearch::HandleChordPingRecv, this));
    m_chord->SetLookupSuccessCallback(MakeCallback(&PennSearch::HandleLookupSuccess, this));
    m_chord->SetLookupFailureCallback(MakeCallback(&PennSearch::HandleLookupFailure, this));
    // Start Chord
    m_chord->SetStartTime(Simulator::Now());
    m_chord->Start();
    if (m_socket == 0) {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        m_socket = Socket::CreateSocket(GetNode(), tid);
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_appPort);
        m_socket->Bind(local);
        m_socket->SetRecvCallback(MakeCallback(&PennSearch::RecvMessage, this));
    }

    // Configure timers
    m_auditPingsTimer.SetFunction(&PennSearch::AuditPings, this);
    // Start timers
    m_auditPingsTimer.Schedule(m_pingTimeout);
}

void
PennSearch::StopApplication(void) {
    //Stop chord
    m_chord->StopChord();
    // Close socket
    if (m_socket) {
        m_socket->Close();
        m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> > ());
        m_socket = 0;
    }

    // Cancel timers
    m_auditPingsTimer.Cancel();
    m_pingTracker.clear();
}

void
PennSearch::ProcessCommand(std::vector<std::string> tokens) {
    std::vector<std::string>::iterator iterator = tokens.begin();
    std::string command = *iterator;
    if (command == "CHORD") {
        // Send to Chord Sub-Layer
        tokens.erase(iterator);
        if ((*iterator).compare("JOIN") == 0 || (*iterator).compare("join") == 0) {
            m_chord->SetJoinCallback(MakeCallback(&PennSearch::chordJoined, this));
        } else if ((*iterator).compare("leave") == 0 || (*iterator).compare("LEAVE") == 0) {
            ProcessLeave();
        }

        m_chord->ProcessCommand(tokens);
    }
    if (command == "PING") {
        if (tokens.size() < 3) {
            ERROR_LOG("Insufficient PING params...");
            return;
        }
        iterator++;
        if (*iterator != "*") {
            std::string nodeId = *iterator;
            iterator++;
            std::string pingMessage = *iterator;
            SendPing(nodeId, pingMessage);
        } else {
            iterator++;
            std::string pingMessage = *iterator;
            std::map<uint32_t, Ipv4Address>::iterator iter;
            for (iter = m_nodeAddressMap.begin(); iter != m_nodeAddressMap.end(); iter++) {
                std::ostringstream sin;
                uint32_t nodeNumber = iter->first;
                sin << nodeNumber;
                std::string nodeId = sin.str();
                SendPing(nodeId, pingMessage);
            }
        }
    }

    //Read file line by line and created inverted 
    //keyword list
    if (command == "PUBLISH") {
        iterator++;
        std::string metadataFile = *iterator;
        char * writable = new char[metadataFile.size() + 1];
        std::copy(metadataFile.begin(), metadataFile.end(), writable);
        writable[metadataFile.size()] = '\0';
        ifstream infile;
        infile.open(writable, ifstream::in);
        std::string s = "";
        //Map of <Key, Document List>
        std::map<std::string, std::vector<string> > inverted;
        while (getline(infile, s)) {
            std::stringstream ss(s);
            std::string item;
            int i = 1;
            //store the document 
            std::string doc;
            getline(ss, doc, ' ');
            while (getline(ss, item, ' ')) {
                std::vector<string> docs;
                //keyword exists in map
                if (inverted.count(item) != 0) {
                    std::map<std::string, std::vector<string> >::iterator it = inverted.find(item);
                    std::vector<string> docs = it->second;
                }
                //add document to doc list and insert into map
                docs.push_back(doc.c_str());
                inverted.insert(std::make_pair(item.c_str(), docs));
                
                SEARCH_LOG ("\nPUBLISH <keyword: " << item << ", docID: " << doc << ">");
                //keep track of how many tokes there are in the string
                i++;
                item.clear();
            }
            doc.clear();
            //junk entry in file
            if (i < 2) {
                ERROR_LOG("\nInsufficient Params in File...\n");
                break;
            }
        }

        //Update the local node publishing-to-do list
        update_publish_list(inverted);
        publish_lookup();

    }

    if (command == "SEARCH") {
        if (tokens.size() < 3) {
            ERROR_LOG("Insufficient SEARCH params...");
            return;
        }

        SearchRes newSearch;
        newSearch.queryNode = m_local;
        iterator++;
        std::string nodeId = *iterator;
        iterator++;
        while (iterator != tokens.end()) {
            newSearch.keywords.push_back(*iterator);
            iterator++;
        }
        Ipv4Address searchAddress = ResolveNodeIpAddress(nodeId);
        if (searchAddress != m_local) {
            //Send list to searchAddress
            SendSearchInit(searchAddress, newSearch);
            //ForwardPartSearch(searchAddress, newSearch);
        } else {
            unsigned char keyHash[SHA_DIGEST_LENGTH];
            unsigned char *keyword = (unsigned char *)newSearch.keywords.front().c_str();
            
            SHA1(keyword, sizeof (keyword), keyHash);
            //DEBUG MESSAGE
            SEARCH_LOG("\nSCH Look Pair Char: " << keyword << ", " << strHash(keyHash) << "\nKeyword size: "<< sizeof (keyword));
 
            uint32_t lookRes = m_chord->Lookup(keyHash);
            m_searchTracker.insert(std::make_pair(lookRes, newSearch));
            newSearch.keywords.clear();        
        }


    } // End Search command

    if (command == "SET4")
      {

    // Populate document list for debugging - comment out actual
    std::string key1 = "HELP";
    //std::string key2 = "MAYBE";
    std::string doc1 = "RLM1";
    std::string doc2 = "RLM2";
    //std::string doc3 = "Doc3";
    std::vector<std::string> inv1;
    inv1.push_back(doc1);
    inv1.push_back(doc2);
    //std::vector<std::string> inv2;
    //inv2.push_back(doc2);
    //inv2.push_back(doc3);
    m_documents.insert(std::make_pair(key1, inv1));
    //m_documents.insert(std::make_pair(key2, inv2));
      }

    if (command == "SET0")
      {

    // Populate document list for debugging - comment out actual
        // std::string key1 = "HELP";
    std::string key2 = "MAYBE";
    //std::string doc1 = "Doc1";
    std::string doc2 = "RLM2";
    std::string doc3 = "RLM3";
    //std::vector<std::string> inv1;
    //inv1.push_back(doc1);
    //inv1.push_back(doc2);
    std::vector<std::string> inv2;
    inv2.push_back(doc2);
    inv2.push_back(doc3);
    //m_documents.insert(std::make_pair(key1, inv1));
    m_documents.insert(std::make_pair(key2, inv2));
      }

}

void
PennSearch::SendPing(std::string nodeId, std::string pingMessage) {
    // Send Ping Via-Chord layer 
    SEARCH_LOG("Sending Ping via Chord Layer to node: " << nodeId << " Message: " << pingMessage);
    Ipv4Address destAddress = ResolveNodeIpAddress(nodeId);
    m_chord->SendPing(destAddress, pingMessage);
}

void
PennSearch::SendPennSearchPing(Ipv4Address destAddress, std::string pingMessage) {
    if (destAddress != Ipv4Address::GetAny()) {
        uint32_t transactionId = GetNextTransactionId();
        SEARCH_LOG("Sending PING_REQ to Node: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
        Ptr<PingRequest> pingRequest = Create<PingRequest> (transactionId, Simulator::Now(), destAddress, pingMessage);
        // Add to ping-tracker
        m_pingTracker.insert(std::make_pair(transactionId, pingRequest));
        Ptr<Packet> packet = Create<Packet> ();
        PennSearchMessage message = PennSearchMessage(PennSearchMessage::PING_REQ, transactionId);
        message.SetPingReq(pingMessage);
        packet->AddHeader(message);
        m_socket->SendTo(packet, 0, InetSocketAddress(destAddress, m_appPort));
    }


}

//Periodic lookup function

void
PennSearch::publish_lookup() {
    //perform lookup's on keywords yet to publish
    for (std::map<std::string, std::vector<std::string> >::iterator iter = m_need_to_publish.begin(); iter != m_need_to_publish.end(); iter++) {
        //only do lookups for those elements which don't already have 
        //a lookup request in progress
        if (m_trackPublish.find(iter->first) == m_trackPublish.end()) {
            unsigned char keyHash[SHA_DIGEST_LENGTH];
            std::string key = iter->first;
            unsigned char *keyword = (unsigned char *)key.c_str();
            
            SHA1(keyword, sizeof (keyword), keyHash);
            //debug messages
            SEARCH_LOG("\nPUB Look Pair Char: " << keyword << ", " << strHash(keyHash) << "\nkeyword: " << sizeof (keyword));
            key.clear();
            //uint32_t lookRes = m_chord->Lookup(keyHash);
            //m_trackPublish.insert(std::make_pair(key, lookRes));
        }
    }
}

void
PennSearch::RecvMessage(Ptr<Socket> socket) {
    Address sourceAddr;
    Ptr<Packet> packet = socket->RecvFrom(sourceAddr);
    InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom(sourceAddr);
    Ipv4Address sourceAddress = inetSocketAddr.GetIpv4();
    uint16_t sourcePort = inetSocketAddr.GetPort();
    PennSearchMessage message;
    packet->RemoveHeader(message);

    switch (message.GetMessageType()) {
        case PennSearchMessage::PING_REQ:
            ProcessPingReq(message, sourceAddress, sourcePort);
            break;
        case PennSearchMessage::PING_RSP:
            ProcessPingRsp(message, sourceAddress, sourcePort);
            break;
        case PennSearchMessage::SEARCH_INIT:
            ProcessSearchInit(message, sourceAddress, sourcePort);
            break;
        case PennSearchMessage::SEARCH_RES:
          // SEARCH_LOG("Got SearchRes...Processing");
            ProcessSearchRes(message, sourceAddress, sourcePort);
            break;
        case PennSearchMessage::SEARCH_FIN:
            ProcessSearchFin(message, sourceAddress, sourcePort);
            break;
        case PennSearchMessage::PUBLISH_RSP:
            ProcessPublishRsp(message, sourceAddress, sourcePort);
            break;
        case PennSearchMessage::PUBLISH_REQ:
            ProcessPublishReq(message, sourceAddress, sourcePort);
            break;
        default:
            ERROR_LOG("Unknown Message Type!");
            break;
    }
}

void
PennSearch::ProcessPingReq(PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {

    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup(sourceAddress);
    SEARCH_LOG("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);
    // Send Ping Response
    PennSearchMessage resp = PennSearchMessage(PennSearchMessage::PING_RSP, message.GetTransactionId());
    resp.SetPingRsp(message.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader(resp);
    m_socket->SendTo(packet, 0, InetSocketAddress(sourceAddress, sourcePort));
}

void
PennSearch::ProcessPingRsp(PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {
    // Remove from pingTracker
    std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
    iter = m_pingTracker.find(message.GetTransactionId());
    if (iter != m_pingTracker.end()) {
        std::string fromNode = ReverseLookup(sourceAddress);
        SEARCH_LOG("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
        m_pingTracker.erase(iter);
    } else {
        DEBUG_LOG("Received invalid PING_RSP!");
    }
}

void
PennSearch::ProcessPublishReq(PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {
    SEARCH_LOG("Received Publish Request from " << sourceAddress);
    // Find all documents in the range, remove them and add them to a publish request.
    std::map<std::string, std::vector<string> > transferMap;

    std::map<std::string, std::vector<string> >::iterator itr = m_documents.begin();
    while (itr != m_documents.end()) {

        // Generate hash for keyword
        const unsigned char *keyword = (const unsigned char *) itr->first.c_str();
        unsigned char location[SHA_DIGEST_LENGTH];
        SHA1(keyword, sizeof (keyword), location);

        // Generate hash for sourceAddress
        unsigned char sourcelocation[SHA_DIGEST_LENGTH];
        uint8_t ip_string[4];
        sourceAddress.Serialize(ip_string);
        SHA1((const unsigned char *) ip_string, sizeof (ip_string), sourcelocation);

        SEARCH_LOG("KEYWORD " << itr->first << "HASHES TO ")
        PrintHash(location, std::cout);
        // Compare range of keyword
        if (RangeCompare(m_chord->getPredecessor().location, location, sourcelocation) == 1) {
            // add to list of keywords to be transferred
            transferMap.insert(*itr);

            // Remove from m_documents
            std::map<std::string, std::vector<string> >::iterator e_itr = itr;
            itr++;
            m_documents.erase(e_itr);

        } else {
            itr++;
        }

        // Send publish with transferMap
        Ptr<Packet> packet = Create<Packet> ();
        PennSearchMessage message = PennSearchMessage(PennSearchMessage::PUBLISH_RSP, GetNextTransactionId());
        message.SetPublishRsp(transferMap);
        packet->AddHeader(message);
        m_socket->SendTo(packet, 0, InetSocketAddress(sourceAddress, m_appPort));



    }

}

void PennSearch::ProcessSearchInit(PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {
    SearchRes newSearch = message.GetSearchInit().searchMessage;
    SEARCH_LOG("Searching for<" << printDocs(newSearch.keywords) << ">");

    unsigned char keyHash[SHA_DIGEST_LENGTH];
    std::cout << newSearch.keywords.front() << std::endl;
    unsigned char *keyword = (unsigned char *)newSearch.keywords.front().c_str();
    std::cout << keyword << std::endl;
    SHA1(keyword, sizeof (keyword), keyHash);
    uint32_t lookRes = m_chord->Lookup(keyHash);
    m_searchTracker.insert(std::make_pair(lookRes, newSearch));
}

void
PennSearch::ProcessSearchRes(PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {
  SEARCH_LOG("SearchRes received from " << sourceAddress);
    SearchRes results = message.GetSearchRsp().searchMessage;

    std::vector<std::string> res;
    if (results.docs.empty()) {
        res = m_documents.find(results.keywords.front())->second;
    } else {
        res = SearchComp(results.keywords.front(), results.docs);
    }

    results.keywords.erase(results.keywords.begin());
    results.docs = res;

    if (res.empty()) {
        SEARCH_LOG("\nSearchResults<" << ReverseLookup(results.queryNode) << ", \"Empty List\">");
        //Send list back to originating node
        SendSearchFin(results.queryNode, results);
        return;
    }
    if (results.keywords.empty()) {
      SEARCH_LOG("\nSearchResults<" << ReverseLookup(results.queryNode) << ", " << printDocs(res) << ">");
        //Send list back to originating node
        SendSearchFin(results.queryNode, results);
        return;
    } else {
        unsigned char keyHash[SHA_DIGEST_LENGTH];
        unsigned char *keyword = (unsigned char *)results.keywords.front().c_str();
        SHA1(keyword, sizeof (keyword), keyHash);
        uint32_t lookRes = m_chord->Lookup(keyHash);
        m_searchTracker.insert(std::make_pair(lookRes, results));
        //lookup hash of kewords.front(), then send keywords and docs to appropriate node
    }

}

void
PennSearch::ProcessSearchFin(PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {
    SearchRes results = message.GetSearchFin().searchMessage;
    SEARCH_LOG("\nSearchResults<" << /*ReverseLookup(*/results.queryNode/*)*/ << ", " << printDocs(results.docs) <<">");
}

std::vector<std::string>
PennSearch::SearchComp(std::string keyword, std::vector<std::string> search_list) {
    std::vector<std::string> results;
    std::map<std::string, std::vector<std::string> >::iterator iter = m_documents.find(keyword);
    if (iter != m_documents.end()) {
        for (std::vector<std::string>::iterator i = search_list.begin(); i != search_list.end(); i++) {
            for (std::vector<std::string>::iterator j = iter->second.begin(); j != iter->second.end(); j++) {
                if (*i == *j) {
                    results.push_back(*i);
                }
            }
        }
    } else {
        DEBUG_LOG("Keyword not found at node");
    }
    return results;
}

void
PennSearch::ForwardPartSearch(Ipv4Address destAddress, SearchRes results) {
    if (destAddress != Ipv4Address::GetAny()) {
        uint32_t transactionId = GetNextTransactionId();
        Ptr<Packet> packet = Create<Packet> ();
        PennSearchMessage message = PennSearchMessage(PennSearchMessage::SEARCH_RES, transactionId);
        message.SetSearchRsp(results);
        packet->AddHeader(message);
        //SEARCH_LOG ("SearchRes packet ready");
        m_socket->SendTo(packet, 0, InetSocketAddress(destAddress, m_appPort));
        //sleep(5);
        //SEARCH_LOG ("SearchRes sent to " << ReverseLookup(destAddress));
    }
}

void
PennSearch::SendSearchInit(Ipv4Address destAddress, SearchRes newSearch) {
    if (destAddress != Ipv4Address::GetAny()) {
        uint32_t transactionId = GetNextTransactionId();
        Ptr<Packet> packet = Create<Packet> ();
        PennSearchMessage message = PennSearchMessage(PennSearchMessage::SEARCH_INIT, transactionId);
        message.SetSearchInit(newSearch);
        packet->AddHeader(message);
        m_socket->SendTo(packet, 0, InetSocketAddress(destAddress, m_appPort));
    }
}

void
PennSearch::SendSearchFin(Ipv4Address destAddress, SearchRes results) {
    if (destAddress != Ipv4Address::GetAny()) {
        uint32_t transactionId = GetNextTransactionId();
        Ptr<Packet> packet = Create<Packet> ();
        PennSearchMessage message = PennSearchMessage(PennSearchMessage::SEARCH_FIN, transactionId);
        message.SetSearchFin(results);
        packet->AddHeader(message);
        m_socket->SendTo(packet, 0, InetSocketAddress(destAddress, m_appPort));
    }
}

void
PennSearch::ProcessSearchLookupResult(Ipv4Address destAddress, SearchRes results) {
    if (results.docs.empty()) {
        SEARCH_LOG("Search<" << printDocs(results.keywords) << ">");
    } else {
      SEARCH_LOG("InvertedListShip<" << results.keywords.front() << ", " << printDocs(results.docs) << ">");
    }
    ForwardPartSearch(destAddress, results);
}

void PennSearch::ProcessPublishRsp(PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort) {
    //SEARCH_LOG("PROCESS_PUBLISH_RSP: NOT YET IMPLEMENTED");
    std::map<std::string, std::vector<std::string> > documents = message.GetPublishRsp().publishMessage;
    //update the local <key, docs> at the node
    update_node(documents);
}

void
PennSearch::AuditPings() {
    std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
    for (iter = m_pingTracker.begin(); iter != m_pingTracker.end();) {
        Ptr<PingRequest> pingRequest = iter->second;
        if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds()) {
            DEBUG_LOG("Ping expired. Message: " << pingRequest->GetPingMessage() << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds() << " CurrentTime: " << Simulator::Now().GetMilliSeconds());
            // Remove stale entries
            m_pingTracker.erase(iter++);
        } else {
            ++iter;
        }
    }
    // Rechedule timer
    m_auditPingsTimer.Schedule(m_pingTimeout);
}

uint32_t
PennSearch::GetNextTransactionId() {
    return m_currentTransactionId++;
}

std::string
PennSearch::printDocs(std::vector<std::string> docList) {
        stringstream s;
    for (std::vector<std::string>::iterator i = docList.begin(); i != docList.end(); i++) {
        s << *i;
        std::vector<std::string>::iterator j = i;
        j++;
        if (j != docList.end()) {
            s << ", ";
        }
    }
    return s.str();
}

// Handle Chord Callbacks

void
PennSearch::HandleChordPingFailure(Ipv4Address destAddress, std::string message) {
    SEARCH_LOG("Chord Ping Expired! Destination nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
}

void
PennSearch::HandleChordPingSuccess(Ipv4Address destAddress, std::string message) {
    SEARCH_LOG("Chord Ping Success! Destination nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
    // Send ping via search layer 
    SendPennSearchPing(destAddress, message);
}

void
PennSearch::HandleChordPingRecv(Ipv4Address destAddress, std::string message) {
    SEARCH_LOG("Chord Layer Received Ping! Source nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
}

void
PennSearch::HandleLookupSuccess(uint8_t *lookupKey, uint8_t lookupKeyBytes, Ipv4Address address, uint32_t transactionId) {
  SEARCH_LOG("Lookup Success " << transactionId << ", IP: " << address);
  inLookup = false;
    map<uint32_t, SearchRes>::iterator iter = m_searchTracker.find(transactionId);
    if (iter != m_searchTracker.end()) {
        SearchRes results = iter->second;
        m_searchTracker.erase(iter);
        ProcessSearchLookupResult(address, results);

    }
    else{
        map<std::string, uint32_t>::iterator itr;
        for(itr=m_trackPublish.begin(); itr!=m_trackPublish.end(); itr++){
            if(transactionId == itr->second){
                std::map<std::string,std::vector<std::string> >::iterator it = m_need_to_publish.find(itr->first);
                if(it != m_need_to_publish.end()){
                std::map<std::string, std::vector<std::string> > message;
                message.insert(std::make_pair(it->first, it->second));
                uint32_t tId = GetNextTransactionId();
                //Send PennSearchMessage to the node with the corresponding <key, doc> map
                PennSearchMessage resp = PennSearchMessage(PennSearchMessage::PUBLISH_RSP, tId);
                resp.SetPublishRsp(message);
                Ptr<Packet> packet = Create<Packet> ();
                packet->AddHeader(resp);
                DEBUG_LOG("\nKeyword: " << it->first << "Node: " << ReverseLookup(address));
                m_socket->SendTo(packet, 0, InetSocketAddress(address, m_appPort));
                
                }
            }
        }
    }
}

void
PennSearch::HandleLookupFailure(uint8_t *lookupKey, uint8_t lookupKeyBytes, uint32_t transactionId) {
  //TODO: restart request on failure and print log
}

    // TODO: Publish lookup 
// Override PennLog

void
PennSearch::SetTrafficVerbose(bool on) {
    m_chord->SetTrafficVerbose(on);
    g_trafficVerbose = on;
}

void
PennSearch::SetErrorVerbose(bool on) {
    m_chord->SetErrorVerbose(on);
    g_errorVerbose = on;
}

void
PennSearch::SetDebugVerbose(bool on) {
    m_chord->SetDebugVerbose(on);
    g_debugVerbose = on;
}

void
PennSearch::SetStatusVerbose(bool on) {
    m_chord->SetStatusVerbose(on);
    g_statusVerbose = on;
}

void
PennSearch::SetChordVerbose(bool on) {
    m_chord->SetChordVerbose(on);
    g_chordVerbose = on;
}

void
PennSearch::SetSearchVerbose(bool on) {
    m_chord->SetSearchVerbose(on);
    g_searchVerbose = on;
}

void PennSearch::update_node(std::map<std::string, std::vector<std::string> > &docs) {
    for (std::map<std::string, std::vector<std::string> >::iterator it = docs.begin(); it != docs.end(); it++) {
        //Keyword doesn't exist
        if (m_documents.find(it->first) == m_documents.end()) {
            m_documents.insert(std::make_pair(it->first, it->second));
            for(std::vector<std::string>::iterator iter = it->second.begin(); iter != it->second.end(); iter++){
              SEARCH_LOG ("\nStore <keyword: " << it->first << ", docID: " << *iter << ">");
            }
        } else { //keyword exists in map
            std::vector<string>::iterator strItr;
            for (strItr = it->second.begin(); strItr != it->second.end(); strItr++) {
                (m_documents.find(it->first)->second).push_back(*strItr);
                SEARCH_LOG ("\nStore <keyword: " << it->first << ", docID: " << *strItr << ">");
            }
        }
    }
    //printing local m_documents to confirm elements were added
    printf("\nPrinting local m_documents\n");
    for(std::map<std::string, std::vector<std::string> >::iterator iter = m_documents.begin(); iter!=m_documents.end(); iter++){
        DEBUG_LOG("\nKEY: " << iter->first);
        for(std::vector<std::string>::iterator itr = iter->second.begin(); itr!=iter->second.end(); itr++){
            DEBUG_LOG("\nDOC: " << *itr);
        }
    }

}

void PennSearch::update_publish_list(std::map<std::string, std::vector<std::string> > &docs) {
    for (std::map<std::string, std::vector<std::string> >::iterator it = docs.begin(); it != docs.end(); it++) {
        if (m_need_to_publish.find(it->first) == m_need_to_publish.end()) {
            m_need_to_publish.insert(std::make_pair(it->first, it->second));
        } else {
            std::vector<string>::iterator strItr;
            for (strItr = it->second.begin(); strItr != it->second.end(); strItr++) {
                (m_need_to_publish.find(it->first)->second).push_back(*strItr);
            }
        }
    }
}

void PennSearch::remove_publish_list(std::vector<std::string> &keys) {

    for (std::vector<std::string>::iterator it = keys.begin(); it != keys.end(); it++) {
        m_need_to_publish.erase(*it);
    }
}

void PennSearch::chordJoined() {
    // TODO this is where we have to send a message that we want to move the associated lists
    std::cout << "Did join callback! Yay!! " << ReverseLookup(m_local) << std::endl;
    NodeInfo suc = m_chord->getSuccessor();

    Ptr<Packet> packet = Create<Packet> ();
    PennSearchMessage message = PennSearchMessage(PennSearchMessage::PUBLISH_REQ, GetNextTransactionId());
    packet->AddHeader(message);
    //packet->Print(std::cout);
    //std::cout << "Dest: " << suc.address << std::endl;
    m_socket->SendTo(packet, 0, InetSocketAddress(suc.address, m_appPort));


}

void PennSearch::ProcessLeave() {
    //Shift all m_documents to successor
    Ptr<Packet> packet = Create<Packet> ();
    PennSearchMessage message = PennSearchMessage(PennSearchMessage::PUBLISH_RSP, GetNextTransactionId());
    message.SetPublishRsp(m_documents);
    packet->AddHeader(message);
    m_socket->SendTo(packet, 0, InetSocketAddress(m_chord->getSuccessor().address, m_appPort));

}
