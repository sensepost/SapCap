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

import java.util.Vector;
import javax.swing.AbstractListModel;

public class SApCapList extends AbstractListModel {

    private Vector g_array = new Vector();
    private int n_update = 0;
    private int moo;

    public int getSize() {
        return g_array.size();
    }

    public Object getElementAt(int i) {
        return g_array.elementAt(i);
    }

    public void ensureCapacity(int i) {
        g_array.ensureCapacity(i);
    }

    public void addElement(Object o) {
        int i = g_array.size();
        n_update = i;
        g_array.addElement(o);
    }

    public void setUpdate() {
        int i = g_array.size();
        fireIntervalAdded(this, n_update, i);
    }

    public void clear() {
        int i = g_array.size() - 1;
        g_array.removeAllElements();
        if (i >= 0) {
            fireIntervalRemoved(this, 0, i);
        }
    }
}
