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

#ifndef PENN_LOG_H
#define PENN_LOG_H

#include <iostream>
#include <string>
#include "ns3/ptr.h"

using namespace ns3;

#define TRAFFIC_LOG(msg)                                              \
  if (g_trafficVerbose)                                               \
    {                                                                 \
      std::cout << "\n*TRAFFIC* Node: " << g_nodeId                   \
                << ", Module: " << g_moduleName                      \
                << ", Time: " << Simulator::Now().GetMilliSeconds()  \
                << " ms, Message:: " << msg << "\n";                   \
    }                                                                 \

#define ERROR_LOG(msg)                                         \
  if (g_errorVerbose)                                               \
    {                                                               \
      std::cout << "\n*ERROR* Node: " << g_nodeId                   \
                << ", Module: " << g_moduleName                      \
                << ", Time: " << Simulator::Now().GetMilliSeconds()  \
                << " ms, Message: " << msg << "\n";                   \
    }                                                               \

#define DEBUG_LOG(msg)                                         \
  if (g_debugVerbose)                                               \
    {                                                               \
      std::cout << "\n*DEBUG* Node: " << g_nodeId                   \
                << ", Module: " << g_moduleName                      \
                << ", Time: " << Simulator::Now().GetMilliSeconds()  \
                << " ms, Message: " << msg << "\n";                   \
    }  
\
#define STATUS_LOG(msg)                                         \
  if (g_statusVerbose)                                               \
    {                                                               \
      std::cout << "\n*STATUS* Node: " << g_nodeId                   \
                << ", Module: " << g_moduleName                      \
                << ", Time: " << Simulator::Now().GetMilliSeconds()  \
                << " ms, Message: " << msg << "\n";                   \
    }       

#define CHORD_LOG(msg)                                         \
  if (g_chordVerbose)                                               \
    {                                                               \
      std::cout << "\n*CHORD* Node: " << g_nodeId                   \
                << ", Module: " << g_moduleName                      \
                << ", Time: " << Simulator::Now().GetMilliSeconds()  \
                << " ms, Message: " << msg << "\n";                   \
    }     

#define SEARCH_LOG(msg)                                         \
  if (g_searchVerbose)                                               \
    {                                                               \
      std::cout << "\n*SEARCH* Node: " << g_nodeId                   \
                << ", Module: " << g_moduleName                      \
                << ", Time: " << Simulator::Now().GetMilliSeconds()  \
                << " ms, Message: " << msg << "\n";                   \
    }     

#define PRINT_LOG(msg)                                         \
      std::cout << msg << "\n";                   

class PennLog 
{
  public:
    PennLog ();
    ~PennLog ();

    // Implemented here
    virtual void SetTrafficVerbose (bool on);
    virtual void SetErrorVerbose (bool on);
    virtual void SetDebugVerbose (bool on);
    virtual void SetStatusVerbose (bool on);
    virtual void SetChordVerbose (bool on);
    virtual void SetSearchVerbose (bool on);
    virtual void SetNodeId (std::string nodeId);
    virtual std::string GetNodeId ();
    virtual void SetModuleName (std::string moduleName);

    std::string g_moduleName;
    std::string g_nodeId;
    bool g_trafficVerbose, g_errorVerbose, g_debugVerbose, g_statusVerbose, g_searchVerbose, g_chordVerbose;
};

#endif
