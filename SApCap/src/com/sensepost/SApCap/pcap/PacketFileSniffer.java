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
import jpcap.JpcapCaptor;
import jpcap.packet.Packet;

public class PacketFileSniffer {
    private SApCap _mainform;
    private JpcapCaptor _netpcap;
    private String _netfilter;
    PacketFileProcessor _processor;
    String _file;

    public PacketFileSniffer(SApCap f, String s, String l) throws Exception {
        this._mainform = f;
        this._file = s;
        this._netfilter = l;
        this._processor = new PacketFileProcessor(this._mainform);
        try {
            this._netpcap = JpcapCaptor.openFile(this._file);
            this._netpcap.setFilter(this._netfilter, true);
            while (true) {
                Packet p = this._netpcap.getPacket();
                if ( (p == null) || (p == Packet.EOF)){
                    break;
                }
                this._processor.receivePacket(p);
            }
            this._netpcap.close();
        }
        catch (Exception e){
            throw new Exception(e.toString());
        }
    }

}
