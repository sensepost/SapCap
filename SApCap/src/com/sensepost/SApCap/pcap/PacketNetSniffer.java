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
import java.io.IOException;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class PacketNetSniffer implements Runnable {

    private SApCap _mainform;
    private JpcapCaptor _netpcap;
    private NetworkInterface _netdevice;
    private String _netfilter;
    private boolean _netpromiscuous;
    private boolean _isrunning;
    private int _droppedpackets;

    public PacketNetSniffer(SApCap f, NetworkInterface n, String s, boolean p) {
        this._mainform = f;
        this._netdevice = n;
        this._netfilter = s;
        this._netpromiscuous = p;
        this._isrunning = false;
        this._droppedpackets = 0;
    }

    public void run() {
        this._isrunning = true;
        try {
            this._netpcap = JpcapCaptor.openDevice(this._netdevice, 65535, this._netpromiscuous, 20);
        } catch (IOException e) {
            this._mainform.addError("Error:" + e.toString());
            this._isrunning = false;
        }
        try {
            this._netpcap.setFilter(this._netfilter, true);
        } catch (Exception e) {
            this._mainform.addError("Error:" + e.toString());
            this._isrunning = false;
        }
        try {
            this._droppedpackets = this._netpcap.loopPacket(-1, new PacketNetProcessor(this._mainform));
        }
        catch (Exception e) {
            this._mainform.addError("Error:" + e.toString());
            this._isrunning = false;
        }
    }

    public synchronized boolean getIsRunning() {
        return this._isrunning;
    }

    public int stopSniffing() {
        this._isrunning = false;
        this._netpcap.breakLoop();
        return this._droppedpackets;
    }

    public JpcapCaptor getCaptor() {
        return this._netpcap;
    }
}
