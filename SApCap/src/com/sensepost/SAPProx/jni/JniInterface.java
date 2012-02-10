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

package com.sensepost.SAPProx.jni;

import java.io.File;

public class JniInterface {

    static {
        File fi = new File (".");
        String di = fi.getAbsolutePath();
        if (!di.endsWith(File.separator)) {
            di = di + File.separator;
        }
        di = di + "lib" + File.separator;
        String os = System.getProperty("os.name");
        String pf = System.getProperty("os.arch");
        // I assume all Os/X is going to 64 bit...
        if (os.toLowerCase().contains("mac")) {
            di += "SapLibOsX64.so";
        }
        else if (os.toLowerCase().contains("windows")) {
            if (pf.contains("64")) {
                di += "SapLibWindows64.dll";
            }
            else {
                di += "SapLibWindows32.dll";
            }
        }
        else if (os.toLowerCase().contains("linux")) {
            if (pf.contains("64")) {
                di += "SapLibLinux64.so";
            }
            else {
                di += "SapLibLinux32.so";
            }
        }
        System.load(di);
        //System.load("/Users/ian/NetBeansProjects/SapCompress/dist/SapLibOsX64.so");
    }

    private native int[] _doDecompress(int[] in);

    private native int[] _doCompress(int[] in);

    public JniInterface() {
    }

    public int[] doDecompress(int[] i) {
        int[] ret;
        ret = this._doDecompress(i);
        return ret;
    }

    public int[] doCompress(int[] i) {
        int[] ret;
        ret = this._doCompress(i);
        return ret;
    }
}
