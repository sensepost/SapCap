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

public class SApCapMessageStructure {

    private String _saddr;
    private int _sport;
    private String _daddr;
    private int _dport;
    private byte[] _comdata;
    private byte[] _decdata;
    private ArrayList _packets;

    public SApCapMessageStructure() {
        this._saddr = "";
        this._sport = -1;
        this._daddr = "";
        this._dport = -1;
        this._comdata = new byte[0];
        this._decdata = new byte[0];
        this._packets = new ArrayList();
    }

    public SApCapMessageStructure(String sa, int sp, String da, int dp, byte[] d, ArrayList p) {
        this._saddr = sa;
        this._sport = sp;
        this._daddr = da;
        this._dport = dp;
        this._comdata = d;
        this._decdata = new byte[0];
        this._packets = p;
    }

    public String getSourceAddress() {
        return this._saddr;
    }

    public void setSourceAddress(String s) {
        this._saddr = s;
    }

    public int getSourcePort() {
        return this._sport;
    }

    public void setSourcePort(int i) {
        this._sport = i;
    }

    public String getDestinationAddress() {
        return this._daddr;
    }

    public void setDestinationAddress(String s) {
        this._daddr = s;
    }

    public int getDestinationPort() {
        return this._dport;
    }

    public void setDestinationPort(int i) {
        this._dport = i;
    }

    public byte[] getCompressedData() {
        return this._comdata;
    }

    public void setCompressedData(byte[] d) {
        this._comdata = d;
    }

    public byte[] getDecompressedData() {
        return this._decdata;
    }

    public void setDecompressedData(byte[] d) {
        this._decdata = d;
    }

    public ArrayList getPackets() {
        return this._packets;
    }

    public void setPackets(ArrayList p) {
        this._packets = p;
    }
}
