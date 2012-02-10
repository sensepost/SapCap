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

package com.sensepost.SApCap.datatype;

import java.util.ArrayList;
import java.util.Hashtable;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class SApCapConnectionStructure {

    private ArrayList _messages;
    private Hashtable _incoming;

    public SApCapConnectionStructure() {
        this._messages = new ArrayList();
        this._incoming = new Hashtable();
    }

    public SApCapConnectionStructure(ArrayList a, Hashtable h) {
        this._messages = a;
        this._incoming = h;
    }

    public ArrayList getMessages() {
        return this._messages;
    }

    public void setMessages(ArrayList a) {
        this._messages = a;
    }

    public Hashtable getIncoming() {
        return this._incoming;
    }

    public void setIncoming(Hashtable h) {
        this._incoming = h;
    }

    public void addIncoming(String k, Packet p) {
        if (p.data.length < 19) {
            ((ArrayList) this._incoming.get(k)).add(p);
        } else {
            if ((((int) p.data[17] & 0xff) == 31) && (((int) p.data[18] & 0xff) == 157)) {
                ArrayList com = new ArrayList();
                ArrayList pac = (ArrayList) this._incoming.get(k);
                for (int i = 0; i < pac.size(); i++) {
                    Packet tp = (Packet) pac.get(i);
                    for (int j = 0; j < tp.data.length; j++) {
                        com.add(tp.data[j]);
                    }
                }
                byte[] bb = new byte[com.size()];
                for (int i = 0; i < com.size(); i++) {
                    bb[i] = ((byte) (Integer.parseInt(com.get(i).toString()) & 0xff));
                }
                ArrayList m = this._messages;
                String si = ((TCPPacket) p).src_ip.toString();
                int sp = ((TCPPacket) p).src_port;
                String di = ((TCPPacket) p).dst_ip.toString();
                int dp = ((TCPPacket) p).dst_port;
                SApCapMessageStructure sms = new SApCapMessageStructure(si, sp, di, dp, bb, pac);
                m.add(sms);
                this._messages = m;
                this._incoming.put(k, new ArrayList());
                ((ArrayList) this._incoming.get(k)).add(p);
            } else {
                ((ArrayList) this._incoming.get(k)).add(p);
            }
        }
    }
}
