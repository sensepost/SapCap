/*
SApCap - SAP Packet Sniffer and decompressor

Copyright (C) 2011 SensePost <ian@sensepost.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.sensepost.SApCap.pcap;

import com.sensepost.SApCap.gui.SApCap;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;

public class PacketNetProcessor implements PacketReceiver {

    private SApCap _mainform;

    public PacketNetProcessor(SApCap f) {
        this._mainform = f;
    }

    public void receivePacket(Packet packet) {
        this._mainform.addPacket(packet);
    }
    
}