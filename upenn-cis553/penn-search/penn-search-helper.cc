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

#include "ns3/penn-search-helper.h"
#include "ns3/penn-search.h"

using namespace ns3;

PennSearchHelper::PennSearchHelper ()
{
  m_factory.SetTypeId (PennSearch::GetTypeId ());
}

void
PennSearchHelper::SetAttribute (std::string name, const AttributeValue &value)
{
  m_factory.Set (name, value);
}

ApplicationContainer
PennSearchHelper::Install (NodeContainer c)
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin () ; i != c.End (); i++)
    {
      Ptr<Node> node = *i;
      Ptr<PennSearch> application = m_factory.Create<PennSearch> ();
      node->AddApplication (application);
      apps.Add (application);
    }
  return apps;
}
