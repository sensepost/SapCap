/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * SaPCap.java
 *
 * Created on Jun 7, 2011, 11:50:07 AM
 */
package com.sensepost.SApCap.gui;

import com.sensepost.SApCap.datatype.SApCapConnectionStructure;
import com.sensepost.SApCap.datatype.SApCapList;
import com.sensepost.SApCap.datatype.SApCapMessageStructure;
import com.sensepost.SApCap.pcap.PacketNetSniffer;
import com.sensepost.SAPProx.jni.JniInterface;
import com.sensepost.SApCap.datatype.KnuthPatternMatching;
import com.sensepost.SApCap.pcap.PacketFileSniffer;
import java.awt.GraphicsEnvironment;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import jpcap.JpcapCaptor;
import jpcap.JpcapWriter;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class SApCap extends javax.swing.JFrame {

    private SApCapList _pcl_connections;
    private Hashtable _connections;
    private SApCapList _pcl_messages;
    private SApCapList _pcl_errors;
    private NetworkInterface[] _netdevices;
    private String _netfilter;
    private boolean _netpromiscuous;
    private boolean _isrunning;
    PacketNetSniffer _captureclass;
    Thread _capturethread;
    JniInterface _jni;

    public synchronized void addError(String s) {
        Date dnow = new Date();
        String e = dnow.toString() + " - " + s;
        this._pcl_errors.addElement(e);
        this._pcl_errors.setUpdate();
    }

    public synchronized void addPacket(Packet p) {
        if (p.data.length > 0) {
            TCPPacket tcp = (TCPPacket) p;
            String k1 = tcp.src_ip.toString() + ":" + Integer.toString(tcp.src_port) + "->" + tcp.dst_ip.toString() + ":" + Integer.toString(tcp.dst_port);
            String k2 = tcp.dst_ip.toString() + ":" + Integer.toString(tcp.dst_port) + "->" + tcp.src_ip.toString() + ":" + Integer.toString(tcp.src_port);
            if (this._connections.containsKey(k1)) {
                SApCapConnectionStructure scs = (SApCapConnectionStructure) this._connections.get(k1);
                Hashtable t = scs.getIncoming();
                if (t.containsKey(k1)) {
                    scs.addIncoming(k1, p);
                } else {
                    ArrayList a = new ArrayList();
                    a.add(p);
                    t.put(k1, a);
                    scs.setIncoming(t);
                }
                this._connections.put(k1, scs);
            } else if (this._connections.containsKey(k2)) {
                SApCapConnectionStructure scs = (SApCapConnectionStructure) this._connections.get(k2);
                Hashtable t = scs.getIncoming();
                if (t.containsKey(k1)) {
                    scs.addIncoming(k1, p);
                } else {
                    ArrayList a = new ArrayList();
                    a.add(p);
                    t.put(k1, a);
                    scs.setIncoming(t);
                }
                this._connections.put(k2, scs);
            } else {
                this._pcl_connections.addElement(k1);
                ArrayList a = new ArrayList();
                a.add(p);
                Hashtable t = new Hashtable();
                t.put(k1, a);
                SApCapConnectionStructure scs = new SApCapConnectionStructure(new ArrayList(), t);
                this._connections.put(k1, scs);
            }
            this._pcl_connections.setUpdate();
            this._pcl_messages.setUpdate();
        }
    }

    private void PopulateNics() {
        this.cbo_nic.removeAllItems();
        this._netdevices = JpcapCaptor.getDeviceList();
        for (int i = 0; i < _netdevices.length; i++) {
            // We want the selection to be: Index: Name: MAC
            String s = "";
            s += _netdevices[i].name;
            s += " : ";
            s += _netdevices[i].datalink_name;
            s += " : ";
            s += _netdevices[i].datalink_description;
            s += " : (";
            for (byte b : _netdevices[i].mac_address) {
                s += Integer.toHexString(b & 0xff) + "-";
            }
            s = s.substring(0, s.length() - 1);
            s += ")";
            this.cbo_nic.addItem(s);
            addError("Adding NiC : " + s);
        }
    }

    /** Creates new form SaPCap */
    public SApCap() {
        this._pcl_connections = new SApCapList();
        this._pcl_connections.setUpdate();
        this._pcl_errors = new SApCapList();
        this._pcl_errors.setUpdate();
        this._pcl_connections.setUpdate();
        this._pcl_messages = new SApCapList();
        this._pcl_messages.setUpdate();
        initComponents();
        addError("SApCap Start Up");
        PopulateNics();
        this.tpn_dec.setEnabledAt(1, false);
        this.tpn_dec.setEnabledAt(2, false);
        this.tpn_dec.setEnabledAt(3, false);
        this.tpn_dec.setEnabledAt(4, false);
        this._isrunning = false;
        this.tpn_main.setSelectedIndex(0);
        this.spn_p_conns.setDividerLocation(200);
        this.spn_messages.setDividerLocation(200);
        this.tpn_main.setSelectedIndex(1);
        this._jni = new JniInterface();
        GraphicsEnvironment e = GraphicsEnvironment.getLocalGraphicsEnvironment();
        this.setMaximizedBounds(e.getMaximumWindowBounds());
        this.setExtendedState(this.getExtendedState()|JFrame.MAXIMIZED_BOTH);
    }

    private void startSniffing() {
        this._connections = new Hashtable();
        this.hex_com.setByteContent(new byte[0]);
        this.hex_dec.setByteContent(new byte[0]);
        this._connections.clear();
        this._pcl_messages.clear();
        this._pcl_messages.setUpdate();
        this._pcl_connections.clear();
        this._pcl_connections.setUpdate();
        this._netfilter = this.txt_filter.getText();
        this._netpromiscuous = this.chk_promiscuous.isSelected();
        try {
            this._captureclass = new PacketNetSniffer(this, this._netdevices[this.cbo_nic.getSelectedIndex()], this._netfilter, this._netpromiscuous);
            this._capturethread = new Thread(this._captureclass);
            this._capturethread.start();
            this._isrunning = true;
            this.btn_start.setText("Stop Sniffing");
            addError("Sniffing Started on " + this.cbo_nic.getSelectedItem().toString());
        } catch (Exception e) {
            addError("Error:" + e.toString());
        }
    }

    private void stopSniffing() {
        try {
            addError("Sniffing Stopping");
            int i = this._captureclass.stopSniffing();
            try {
                this._capturethread.join();
                addError("Sniffing Stopped");
            } catch (Exception e) {
                addError("Error:" + e.toString());
            }
            this._isrunning = false;
            this.btn_start.setText("Start Sniffing");
            this._netfilter = "";
            this._netpromiscuous = false;
        } catch (Exception e) {
            addError("Error:" + e.toString());
        }
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        mnu_connections = new javax.swing.JPopupMenu();
        mnu_csave = new javax.swing.JMenu();
        mni_csavell = new javax.swing.JMenuItem();
        mni_csaveselected = new javax.swing.JMenuItem();
        mnu_cclear = new javax.swing.JMenuItem();
        mnu_messages = new javax.swing.JPopupMenu();
        mnu_msave = new javax.swing.JMenu();
        mni_msaveall = new javax.swing.JMenuItem();
        mni_msaveselected = new javax.swing.JMenuItem();
        mnu_mexport = new javax.swing.JMenu();
        mnu_mcompressed = new javax.swing.JMenu();
        mni_mcexportselected = new javax.swing.JMenuItem();
        mnu_mdecompressed = new javax.swing.JMenu();
        mni_mdexportselected = new javax.swing.JMenuItem();
        mnu_mclear = new javax.swing.JMenuItem();
        mnu_error = new javax.swing.JPopupMenu();
        mni_esave = new javax.swing.JMenuItem();
        mni_eclear = new javax.swing.JMenuItem();
        tpn_main = new javax.swing.JTabbedPane();
        pnl_main = new javax.swing.JPanel();
        spn_p_conns = new javax.swing.JSplitPane();
        pnl_p_conns = new javax.swing.JPanel();
        spn_p_cons = new javax.swing.JScrollPane();
        lst_cons = new javax.swing.JList();
        spn_messages = new javax.swing.JSplitPane();
        pnl_messages = new javax.swing.JPanel();
        scp_messages = new javax.swing.JScrollPane();
        lst_messages = new javax.swing.JList();
        pnl_themessage = new javax.swing.JPanel();
        pnl_themessageoverview = new javax.swing.JPanel();
        lbl_s1 = new javax.swing.JLabel();
        lbl_d1 = new javax.swing.JLabel();
        lbl_s2 = new javax.swing.JLabel();
        lbl_d2 = new javax.swing.JLabel();
        tpn_message = new javax.swing.JTabbedPane();
        pnl_dec = new javax.swing.JPanel();
        tpn_dec = new javax.swing.JTabbedPane();
        hex_dec = new at.HexLib.library.JHexEditor();
        pnl_params = new javax.swing.JPanel();
        hex_params = new at.HexLib.library.JHexEditor();
        pnl_rfc = new javax.swing.JPanel();
        hex_rfc = new at.HexLib.library.JHexEditor();
        pnl_verbs = new javax.swing.JPanel();
        hex_verbs = new at.HexLib.library.JHexEditor();
        pnl_vars = new javax.swing.JPanel();
        hex_vars = new at.HexLib.library.JHexEditor();
        pnl_com = new javax.swing.JPanel();
        hex_com = new at.HexLib.library.JHexEditor();
        pnl_config = new javax.swing.JPanel();
        lbl_nic = new javax.swing.JLabel();
        cbo_nic = new javax.swing.JComboBox();
        btn_refresh = new javax.swing.JButton();
        lbl_filter = new javax.swing.JLabel();
        txt_filter = new javax.swing.JTextField();
        chk_promiscuous = new javax.swing.JCheckBox();
        btn_start = new javax.swing.JButton();
        btn_load = new javax.swing.JButton();
        pnl_log = new javax.swing.JPanel();
        spn_log = new javax.swing.JScrollPane();
        lst_log = new javax.swing.JList();

        mnu_csave.setText("Save");

        mni_csavell.setText("Save All");
        mni_csavell.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mni_csavellActionPerformed(evt);
            }
        });
        mnu_csave.add(mni_csavell);

        mni_csaveselected.setText("Save Selected");
        mni_csaveselected.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mni_csaveselectedActionPerformed(evt);
            }
        });
        mnu_csave.add(mni_csaveselected);

        mnu_connections.add(mnu_csave);

        mnu_cclear.setText("Clear List");
        mnu_cclear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mnu_cclearActionPerformed(evt);
            }
        });
        mnu_connections.add(mnu_cclear);

        mnu_msave.setText("Save");

        mni_msaveall.setText("Save All");
        mni_msaveall.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mni_msaveallActionPerformed(evt);
            }
        });
        mnu_msave.add(mni_msaveall);

        mni_msaveselected.setText("Save Selected");
        mni_msaveselected.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mni_msaveselectedActionPerformed(evt);
            }
        });
        mnu_msave.add(mni_msaveselected);

        mnu_messages.add(mnu_msave);

        mnu_mexport.setText("Export");

        mnu_mcompressed.setText("Compressed");

        mni_mcexportselected.setText("Export Selected Compressed");
        mni_mcexportselected.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mni_mcexportselectedActionPerformed(evt);
            }
        });
        mnu_mcompressed.add(mni_mcexportselected);

        mnu_mexport.add(mnu_mcompressed);

        mnu_mdecompressed.setText("Decompressed");

        mni_mdexportselected.setText("Export Selected Decompressed");
        mni_mdexportselected.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mni_mdexportselectedActionPerformed(evt);
            }
        });
        mnu_mdecompressed.add(mni_mdexportselected);

        mnu_mexport.add(mnu_mdecompressed);

        mnu_messages.add(mnu_mexport);

        mnu_mclear.setText("Clear List");
        mnu_mclear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mnu_mclearActionPerformed(evt);
            }
        });
        mnu_messages.add(mnu_mclear);

        mni_esave.setText("Save Log");
        mni_esave.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mni_esaveActionPerformed(evt);
            }
        });
        mnu_error.add(mni_esave);

        mni_eclear.setText("Clear List");
        mni_eclear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mni_eclearActionPerformed(evt);
            }
        });
        mnu_error.add(mni_eclear);

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("SApCap by SensePost...");
        addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentResized(java.awt.event.ComponentEvent evt) {
                formComponentResized(evt);
            }
        });

        spn_p_conns.setDividerLocation(200);
        spn_p_conns.setOneTouchExpandable(true);

        pnl_p_conns.setBorder(javax.swing.BorderFactory.createTitledBorder("Connections"));

        lst_cons.setModel(this._pcl_connections);
        lst_cons.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        lst_cons.setComponentPopupMenu(mnu_connections);
        lst_cons.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
            public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                lst_consValueChanged(evt);
            }
        });
        spn_p_cons.setViewportView(lst_cons);

        org.jdesktop.layout.GroupLayout pnl_p_connsLayout = new org.jdesktop.layout.GroupLayout(pnl_p_conns);
        pnl_p_conns.setLayout(pnl_p_connsLayout);
        pnl_p_connsLayout.setHorizontalGroup(
            pnl_p_connsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 186, Short.MAX_VALUE)
            .add(pnl_p_connsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(spn_p_cons, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
        );
        pnl_p_connsLayout.setVerticalGroup(
            pnl_p_connsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 580, Short.MAX_VALUE)
            .add(pnl_p_connsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(spn_p_cons, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
        );

        spn_p_conns.setLeftComponent(pnl_p_conns);

        spn_messages.setOneTouchExpandable(true);

        pnl_messages.setBorder(javax.swing.BorderFactory.createTitledBorder("Messages"));

        lst_messages.setModel(this._pcl_messages);
        lst_messages.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        lst_messages.setComponentPopupMenu(mnu_messages);
        lst_messages.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
            public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                lst_messagesValueChanged(evt);
            }
        });
        scp_messages.setViewportView(lst_messages);

        org.jdesktop.layout.GroupLayout pnl_messagesLayout = new org.jdesktop.layout.GroupLayout(pnl_messages);
        pnl_messages.setLayout(pnl_messagesLayout);
        pnl_messagesLayout.setHorizontalGroup(
            pnl_messagesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 23, Short.MAX_VALUE)
            .add(pnl_messagesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(scp_messages, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 23, Short.MAX_VALUE))
        );
        pnl_messagesLayout.setVerticalGroup(
            pnl_messagesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 576, Short.MAX_VALUE)
            .add(pnl_messagesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(scp_messages, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 576, Short.MAX_VALUE))
        );

        spn_messages.setLeftComponent(pnl_messages);

        pnl_themessageoverview.setBorder(javax.swing.BorderFactory.createTitledBorder("Message Overview"));

        lbl_s1.setText("Source:");

        lbl_d1.setText("Destination:");

        org.jdesktop.layout.GroupLayout pnl_themessageoverviewLayout = new org.jdesktop.layout.GroupLayout(pnl_themessageoverview);
        pnl_themessageoverview.setLayout(pnl_themessageoverviewLayout);
        pnl_themessageoverviewLayout.setHorizontalGroup(
            pnl_themessageoverviewLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnl_themessageoverviewLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnl_themessageoverviewLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING, false)
                    .add(org.jdesktop.layout.GroupLayout.LEADING, lbl_d1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .add(org.jdesktop.layout.GroupLayout.LEADING, lbl_s1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 99, Short.MAX_VALUE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(pnl_themessageoverviewLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(lbl_d2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 719, Short.MAX_VALUE)
                    .add(lbl_s2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 719, Short.MAX_VALUE))
                .addContainerGap())
        );
        pnl_themessageoverviewLayout.setVerticalGroup(
            pnl_themessageoverviewLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnl_themessageoverviewLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnl_themessageoverviewLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(lbl_s1)
                    .add(lbl_s2))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnl_themessageoverviewLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(lbl_d1)
                    .add(lbl_d2))
                .addContainerGap(8, Short.MAX_VALUE))
        );

        hex_dec.setMinimumSize(new java.awt.Dimension(300, 17));
        tpn_dec.addTab("Message", hex_dec);

        org.jdesktop.layout.GroupLayout pnl_paramsLayout = new org.jdesktop.layout.GroupLayout(pnl_params);
        pnl_params.setLayout(pnl_paramsLayout);
        pnl_paramsLayout.setHorizontalGroup(
            pnl_paramsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 842, Short.MAX_VALUE)
            .add(pnl_paramsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(hex_params, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE))
        );
        pnl_paramsLayout.setVerticalGroup(
            pnl_paramsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 391, Short.MAX_VALUE)
            .add(pnl_paramsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(hex_params, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE))
        );

        tpn_dec.addTab("PARAMS", pnl_params);

        org.jdesktop.layout.GroupLayout pnl_rfcLayout = new org.jdesktop.layout.GroupLayout(pnl_rfc);
        pnl_rfc.setLayout(pnl_rfcLayout);
        pnl_rfcLayout.setHorizontalGroup(
            pnl_rfcLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 842, Short.MAX_VALUE)
            .add(pnl_rfcLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(hex_rfc, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE))
        );
        pnl_rfcLayout.setVerticalGroup(
            pnl_rfcLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 391, Short.MAX_VALUE)
            .add(pnl_rfcLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(hex_rfc, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE))
        );

        tpn_dec.addTab("RFC_QUEUE", pnl_rfc);

        org.jdesktop.layout.GroupLayout pnl_verbsLayout = new org.jdesktop.layout.GroupLayout(pnl_verbs);
        pnl_verbs.setLayout(pnl_verbsLayout);
        pnl_verbsLayout.setHorizontalGroup(
            pnl_verbsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 842, Short.MAX_VALUE)
            .add(pnl_verbsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(hex_verbs, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE))
        );
        pnl_verbsLayout.setVerticalGroup(
            pnl_verbsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 391, Short.MAX_VALUE)
            .add(pnl_verbsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(hex_verbs, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE))
        );

        tpn_dec.addTab("VERBS", pnl_verbs);

        org.jdesktop.layout.GroupLayout pnl_varsLayout = new org.jdesktop.layout.GroupLayout(pnl_vars);
        pnl_vars.setLayout(pnl_varsLayout);
        pnl_varsLayout.setHorizontalGroup(
            pnl_varsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 842, Short.MAX_VALUE)
            .add(pnl_varsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(hex_vars, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE))
        );
        pnl_varsLayout.setVerticalGroup(
            pnl_varsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 391, Short.MAX_VALUE)
            .add(pnl_varsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(hex_vars, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE))
        );

        tpn_dec.addTab("VARS", pnl_vars);

        org.jdesktop.layout.GroupLayout pnl_decLayout = new org.jdesktop.layout.GroupLayout(pnl_dec);
        pnl_dec.setLayout(pnl_decLayout);
        pnl_decLayout.setHorizontalGroup(
            pnl_decLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(tpn_dec, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 863, Short.MAX_VALUE)
        );
        pnl_decLayout.setVerticalGroup(
            pnl_decLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(tpn_dec, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 437, Short.MAX_VALUE)
        );

        tpn_message.addTab("Decompressed", pnl_dec);

        org.jdesktop.layout.GroupLayout pnl_comLayout = new org.jdesktop.layout.GroupLayout(pnl_com);
        pnl_com.setLayout(pnl_comLayout);
        pnl_comLayout.setHorizontalGroup(
            pnl_comLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 863, Short.MAX_VALUE)
            .add(pnl_comLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(hex_com, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 863, Short.MAX_VALUE))
        );
        pnl_comLayout.setVerticalGroup(
            pnl_comLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 437, Short.MAX_VALUE)
            .add(pnl_comLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(hex_com, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 437, Short.MAX_VALUE))
        );

        tpn_message.addTab("Compressed", pnl_com);

        org.jdesktop.layout.GroupLayout pnl_themessageLayout = new org.jdesktop.layout.GroupLayout(pnl_themessage);
        pnl_themessage.setLayout(pnl_themessageLayout);
        pnl_themessageLayout.setHorizontalGroup(
            pnl_themessageLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 884, Short.MAX_VALUE)
            .add(pnl_themessageLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(org.jdesktop.layout.GroupLayout.TRAILING, pnl_themessageoverview, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .add(pnl_themessageLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(tpn_message, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 884, Short.MAX_VALUE))
        );
        pnl_themessageLayout.setVerticalGroup(
            pnl_themessageLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 604, Short.MAX_VALUE)
            .add(pnl_themessageLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(pnl_themessageLayout.createSequentialGroup()
                    .addContainerGap()
                    .add(pnl_themessageoverview, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 96, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(488, Short.MAX_VALUE)))
            .add(pnl_themessageLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(pnl_themessageLayout.createSequentialGroup()
                    .add(121, 121, 121)
                    .add(tpn_message, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 483, Short.MAX_VALUE)))
        );

        spn_messages.setRightComponent(pnl_themessage);

        spn_p_conns.setRightComponent(spn_messages);

        org.jdesktop.layout.GroupLayout pnl_mainLayout = new org.jdesktop.layout.GroupLayout(pnl_main);
        pnl_main.setLayout(pnl_mainLayout);
        pnl_mainLayout.setHorizontalGroup(
            pnl_mainLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 1143, Short.MAX_VALUE)
            .add(pnl_mainLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(org.jdesktop.layout.GroupLayout.TRAILING, spn_p_conns, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 1143, Short.MAX_VALUE))
        );
        pnl_mainLayout.setVerticalGroup(
            pnl_mainLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 612, Short.MAX_VALUE)
            .add(pnl_mainLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(org.jdesktop.layout.GroupLayout.TRAILING, spn_p_conns, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 612, Short.MAX_VALUE))
        );

        tpn_main.addTab("SAP Connections & Messages", pnl_main);

        lbl_nic.setLabelFor(cbo_nic);
        lbl_nic.setText("Network Interface:");

        btn_refresh.setText("Refresh");
        btn_refresh.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_refreshActionPerformed(evt);
            }
        });

        lbl_filter.setLabelFor(txt_filter);
        lbl_filter.setText("Capture Filter:");

        txt_filter.setText("ip and tcp and port 3200");

        chk_promiscuous.setText("Promiscuous Mode");

        btn_start.setText("Start Sniffing...");
        btn_start.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_startActionPerformed(evt);
            }
        });

        btn_load.setText("Load from File...");
        btn_load.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_loadActionPerformed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout pnl_configLayout = new org.jdesktop.layout.GroupLayout(pnl_config);
        pnl_config.setLayout(pnl_configLayout);
        pnl_configLayout.setHorizontalGroup(
            pnl_configLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnl_configLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnl_configLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnl_configLayout.createSequentialGroup()
                        .add(pnl_configLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(lbl_nic)
                            .add(lbl_filter))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(pnl_configLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(pnl_configLayout.createSequentialGroup()
                                .add(cbo_nic, 0, 830, Short.MAX_VALUE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(btn_refresh, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 141, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                            .add(txt_filter, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 977, Short.MAX_VALUE)))
                    .add(chk_promiscuous)
                    .add(btn_start, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 143, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(btn_load))
                .addContainerGap())
        );
        pnl_configLayout.setVerticalGroup(
            pnl_configLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnl_configLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnl_configLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(lbl_nic)
                    .add(cbo_nic, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(btn_refresh))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnl_configLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(lbl_filter)
                    .add(txt_filter, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(chk_promiscuous)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(btn_start)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(btn_load)
                .addContainerGap(440, Short.MAX_VALUE))
        );

        tpn_main.addTab("Configuration & Control", pnl_config);

        lst_log.setModel(this._pcl_errors);
        lst_log.setComponentPopupMenu(mnu_error);
        spn_log.setViewportView(lst_log);

        org.jdesktop.layout.GroupLayout pnl_logLayout = new org.jdesktop.layout.GroupLayout(pnl_log);
        pnl_log.setLayout(pnl_logLayout);
        pnl_logLayout.setHorizontalGroup(
            pnl_logLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 1143, Short.MAX_VALUE)
            .add(pnl_logLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(spn_log, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 1143, Short.MAX_VALUE))
        );
        pnl_logLayout.setVerticalGroup(
            pnl_logLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 612, Short.MAX_VALUE)
            .add(pnl_logLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(spn_log, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 612, Short.MAX_VALUE))
        );

        tpn_main.addTab("Log", pnl_log);

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 1164, Short.MAX_VALUE)
            .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(tpn_main, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 1164, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(0, 658, Short.MAX_VALUE)
            .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                .add(tpn_main, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 658, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btn_startActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_startActionPerformed
        if (this._isrunning) {
            stopSniffing();
        } else {
            startSniffing();
            this.tpn_main.setSelectedIndex(0);
        }
    }//GEN-LAST:event_btn_startActionPerformed

    private void btn_refreshActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_refreshActionPerformed
        PopulateNics();
    }//GEN-LAST:event_btn_refreshActionPerformed

    private void lst_consValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_lst_consValueChanged
        try {
            SApCapConnectionStructure scs = (SApCapConnectionStructure) this._connections.get(this.lst_cons.getSelectedValue().toString());
            ArrayList a = (ArrayList) scs.getMessages();
            this._pcl_messages.clear();
            for (int i = 0; i < a.size(); i++) {
                SApCapMessageStructure scm = (SApCapMessageStructure) a.get(i);
                String s = Integer.toString(i) + ": " + scm.getSourceAddress() + ":" + Integer.toString(scm.getSourcePort()) + " -> " + scm.getDestinationAddress() + ":" + Integer.toString(scm.getDestinationPort());
                this._pcl_messages.addElement(s);
            }
            this._pcl_messages.setUpdate();
        } catch (Exception e) {
            this._pcl_messages.clear();
            this._pcl_messages.setUpdate();
        }
    }//GEN-LAST:event_lst_consValueChanged

    private void setSubBytes(int[] ia) {

        int[] PARAMS = {0x50, 0x41, 0x52, 0x41, 0x4d, 0x53, 0x03, 0x01, 0x03};
        int[] RFCQUEUE = {0x52, 0x46, 0x43, 0x5f, 0x51, 0x55, 0x45, 0x55, 0x45, 0x03, 0x01, 0x03};
        int[] VARS = {0x56, 0x41, 0x52, 0x53, 0x03, 0x01, 0x03};
        int[] VERBS = {0x56, 0x45, 0x52, 0x42, 0x53, 0x03, 0x01, 0x03};
        int[] MAGIC = {0x1f, 0x9d};

        int paramstart = KnuthPatternMatching.indexOf(ia, PARAMS, 0);
        int rfcqueuestart = KnuthPatternMatching.indexOf(ia, RFCQUEUE, 0);
        int varsstart = KnuthPatternMatching.indexOf(ia, VARS, 0);
        int verbsstart = KnuthPatternMatching.indexOf(ia, VERBS, 0);

        boolean b_params = false;
        boolean b_rfc = false;
        boolean b_vars = false;
        boolean b_verbs = false;

        if (paramstart > -1) {
            // Extract Stream over here...
            int n_m = KnuthPatternMatching.indexOf(ia, MAGIC, paramstart);
            if (n_m > -1) {
                n_m = n_m - 17;
                int[] params = new int[ia.length - n_m];
                System.arraycopy(ia, n_m, params, 0, ia.length - n_m);
                int[] pdec = this._jni.doDecompress(params);
                byte[] _params = new byte[pdec.length];
                for (int z = 0; z < pdec.length; z++) {
                    _params[z] = (byte) pdec[z];
                }
                this.hex_params.setByteContent(_params);
                b_params = true;
            }
        }
        if (rfcqueuestart > -1) {
            int n_m = KnuthPatternMatching.indexOf(ia, MAGIC, rfcqueuestart);
            if (n_m > -1) {
                n_m = n_m - 17;
                int[] rfc = new int[ia.length - n_m];
                System.arraycopy(ia, n_m, rfc, 0, ia.length - n_m);
                int[] pdec = this._jni.doDecompress(rfc);
                byte[] _rfcqueue = new byte[pdec.length];
                for (int z = 0; z < pdec.length; z++) {
                    _rfcqueue[z] = (byte) pdec[z];
                }
                this.hex_rfc.setByteContent(_rfcqueue);
                b_rfc = true;
            }
        }
        if (varsstart > -1) {
            int n_m = KnuthPatternMatching.indexOf(ia, MAGIC, varsstart);
            if (n_m > -1) {
                n_m = n_m - 17;
                int[] vars = new int[ia.length - n_m];
                System.arraycopy(ia, n_m, vars, 0, ia.length - n_m);
                int[] pdec = this._jni.doDecompress(vars);
                byte[] _vars = new byte[pdec.length];
                for (int z = 0; z < pdec.length; z++) {
                    _vars[z] = (byte) pdec[z];
                }
                this.hex_vars.setByteContent(_vars);
                b_vars = true;
            }
        }
        if (verbsstart > -1) {
            int n_m = KnuthPatternMatching.indexOf(ia, MAGIC, verbsstart);
            if (n_m > -1) {
                n_m = n_m - 17;
                int[] verbs = new int[ia.length - n_m];
                System.arraycopy(ia, n_m, verbs, 0, ia.length - n_m);
                int[] pdec = this._jni.doDecompress(verbs);
                byte[] _verbs = new byte[pdec.length];
                for (int z = 0; z < pdec.length; z++) {
                    _verbs[z] = (byte) pdec[z];
                }
                this.hex_verbs.setByteContent(_verbs);
                b_verbs = true;
            }
        }
        this.tpn_dec.setEnabledAt(1, b_params);
        this.tpn_dec.setEnabledAt(2, b_rfc);
        this.tpn_dec.setEnabledAt(3, b_verbs);
        this.tpn_dec.setEnabledAt(4, b_vars);
    }

    private void lst_messagesValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_lst_messagesValueChanged
        // We will have to add stuff here to...
        // a: Parse decompressed message.
        // b: Enable PARAMS, VARS, VERBS, RFCQ dependant on data
        try {
            String s = lst_messages.getSelectedValue().toString();
            String[] n = s.split(":");
            int i = Integer.parseInt(n[0]);
            SApCapConnectionStructure scs = (SApCapConnectionStructure) this._connections.get(this.lst_cons.getSelectedValue().toString());
            SApCapMessageStructure sms = (SApCapMessageStructure) scs.getMessages().get(i);
            this.lbl_s2.setText(sms.getSourceAddress() + ":" + Integer.toString(sms.getSourcePort()));
            this.lbl_d2.setText(sms.getDestinationAddress() + ":" + Integer.toString(sms.getDestinationPort()));
            byte[] com = sms.getCompressedData();
            this.hex_com.setByteContent(com);
            if ((((int) com[17] & 0xff) == 31) && (((int) com[18] & 0xff) == 157)) {
                int[] ia = new int[com.length];
                for (int z = 0; z < ia.length; z++) {
                    ia[z] = (int) com[z] & 0xff;
                }
                int[] da = this._jni.doDecompress(ia);

                // We selected the default tabs...  Decompressed for message overview.  Message for message analysis
                this.tpn_message.setSelectedIndex(0);
                this.tpn_dec.setSelectedIndex(0);

                // This is where we will set the sub byte stuff...
                setSubBytes(da);


                byte[] dec = new byte[da.length];
                for (int z = 0; z < da.length; z++) {
                    dec[z] = (byte) da[z];
                }
                this.hex_dec.setByteContent(dec);
            } else {
                String ss = "UNCOMPRESSED OR MISSING PACKETS";
                char[] cec = ss.toCharArray();
                byte[] dec = new byte[cec.length];
                for (int zz = 0; zz < dec.length; zz++) {
                    dec[zz] = (byte) cec[zz];
                }
                this.hex_dec.setByteContent(dec);
            }
        } catch (Exception e) {
            this.hex_com.setByteContent(new byte[0]);
            this.hex_dec.setByteContent(new byte[0]);
        }
    }//GEN-LAST:event_lst_messagesValueChanged

    private void SavePackets(ArrayList p) {
        if (this._isrunning) {
            int n = JOptionPane.showOptionDialog(this, "You will have to stop sniffing before saving. Stop sniffing now ?", "Save Selected Packets", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, null, JOptionPane.YES_OPTION);
            if (n != JOptionPane.YES_OPTION) {
                return;
            }
        }
        this.stopSniffing();
        JFileChooser f_chooser = new JFileChooser();
        int status = f_chooser.showSaveDialog(this);
        if (status == JFileChooser.APPROVE_OPTION) {
            String f_filename = f_chooser.getSelectedFile().toString();
            SApCapConnectionStructure scs = (SApCapConnectionStructure) this._connections.get(this.lst_cons.getSelectedValue().toString());
            try {
                JpcapWriter cap_write = JpcapWriter.openDumpFile(this._captureclass.getCaptor(), f_filename);
                for (int i = 0; i < p.size(); i++) {
                    Packet pac = (Packet) p.get(i);
                    cap_write.writePacket(pac);
                }
            } catch (Exception e) {
                addError("Error:" + e.toString());
                JOptionPane.showMessageDialog(this, "Could not save the packets:\n" + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
        } else {
            JOptionPane.showMessageDialog(this, "Packet save cancelled", "Saved", JOptionPane.PLAIN_MESSAGE);
            return;
        }
        addError("Packets saved to file");
        JOptionPane.showMessageDialog(this, "Packets Saved", "Saved", JOptionPane.PLAIN_MESSAGE);
    }

    private void mni_msaveallActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mni_msaveallActionPerformed
        SApCapConnectionStructure scs = (SApCapConnectionStructure) this._connections.get(this.lst_cons.getSelectedValue().toString());
        ArrayList p = new ArrayList();
        ArrayList a = (ArrayList) scs.getMessages();
        for (int i = 0; i < a.size(); i++) {
            SApCapMessageStructure scm = (SApCapMessageStructure) a.get(i);
            ArrayList pdata = (ArrayList) scm.getPackets();
            for (int j = 0; j < pdata.size(); j++) {
                p.add((Packet) pdata.get(j));
            }
        }
        SavePackets(p);
    }//GEN-LAST:event_mni_msaveallActionPerformed

    private void mni_csavellActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mni_csavellActionPerformed
        ArrayList p = new ArrayList();
        Enumeration e = this._connections.keys();
        while (e.hasMoreElements()) {
            String s = e.nextElement().toString();
            SApCapConnectionStructure scs = (SApCapConnectionStructure) this._connections.get(this.lst_cons.getSelectedValue().toString());
            ArrayList a = (ArrayList) scs.getMessages();
            for (int i = 0; i < a.size(); i++) {
                SApCapMessageStructure scm = (SApCapMessageStructure) a.get(i);
                ArrayList pdata = (ArrayList) scm.getPackets();
                for (int j = 0; j < pdata.size(); j++) {
                    p.add((Packet) pdata.get(j));
                }
            }
        }
        SavePackets(p);
    }//GEN-LAST:event_mni_csavellActionPerformed

    private void mni_csaveselectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mni_csaveselectedActionPerformed
        SApCapConnectionStructure scs = (SApCapConnectionStructure) this._connections.get(this.lst_cons.getSelectedValue().toString());
        ArrayList p = new ArrayList();
        ArrayList a = (ArrayList) scs.getMessages();
        for (int i = 0; i < a.size(); i++) {
            SApCapMessageStructure scm = (SApCapMessageStructure) a.get(i);
            ArrayList pdata = (ArrayList) scm.getPackets();
            for (int j = 0; j < pdata.size(); j++) {
                p.add((Packet) pdata.get(j));
            }
        }
        SavePackets(p);
    }//GEN-LAST:event_mni_csaveselectedActionPerformed

    private void mni_msaveselectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mni_msaveselectedActionPerformed
        String s = lst_messages.getSelectedValue().toString();
        String[] n = s.split(":");
        int i = Integer.parseInt(n[0]);
        SApCapConnectionStructure scs = (SApCapConnectionStructure) this._connections.get(this.lst_cons.getSelectedValue().toString());
        SApCapMessageStructure sms = (SApCapMessageStructure) scs.getMessages().get(i);
        ArrayList p = new ArrayList();
        ArrayList a = (ArrayList) sms.getPackets();
        for (int j = 0; j < a.size(); j++) {
            p.add((Packet) a.get(j));
        }
        SavePackets(p);
    }//GEN-LAST:event_mni_msaveselectedActionPerformed

    private void btn_loadActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_loadActionPerformed
        if (this._isrunning) {
            int n = JOptionPane.showOptionDialog(this, "You will have to stop sniffing before loading. Stop sniffing now ?", "Load Packets", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, null, JOptionPane.YES_OPTION);
            if (n != JOptionPane.YES_OPTION) {
                return;
            }
        }
        this.stopSniffing();
        this._connections = new Hashtable();
        this.hex_com.setByteContent(new byte[0]);
        this.hex_dec.setByteContent(new byte[0]);
        this._connections.clear();
        this._pcl_messages.clear();
        this._pcl_messages.setUpdate();
        this._pcl_connections.clear();
        this._pcl_connections.setUpdate();
        this._netfilter = this.txt_filter.getText();
        this.stopSniffing();
        JFileChooser f_chooser = new JFileChooser();
        int status = f_chooser.showOpenDialog(this);
        if (status == JFileChooser.APPROVE_OPTION) {
            String f_filename = f_chooser.getSelectedFile().toString();
            try {
                PacketFileSniffer pfr = new PacketFileSniffer(this, f_filename, this.txt_filter.getText());
            } catch (Exception e) {
                addError("Error:" + e.toString());
                JOptionPane.showMessageDialog(this, "Could not load the packets:\n" + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
        } else {
            JOptionPane.showMessageDialog(this, "Packet load cancelled", "Load", JOptionPane.PLAIN_MESSAGE);
            return;
        }
        addError("Packets loaded from file");
        JOptionPane.showMessageDialog(this, "Packets Loaded", "Loaded", JOptionPane.PLAIN_MESSAGE);
        this.tpn_main.setSelectedIndex(0);
    }//GEN-LAST:event_btn_loadActionPerformed

    private void mnu_cclearActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mnu_cclearActionPerformed
        this._connections.clear();
        this.hex_com.setByteContent(new byte[0]);
        this.hex_dec.setByteContent(new byte[0]);
        this._pcl_messages.clear();
        this._pcl_messages.setUpdate();
        this._pcl_connections.clear();
        this._pcl_connections.setUpdate();
    }//GEN-LAST:event_mnu_cclearActionPerformed

    private void mnu_mclearActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mnu_mclearActionPerformed
        this._connections.clear();
        this.hex_com.setByteContent(new byte[0]);
        this.hex_dec.setByteContent(new byte[0]);
        this._pcl_messages.clear();
        this._pcl_messages.setUpdate();
        this._pcl_connections.clear();
        this._pcl_connections.setUpdate();
    }//GEN-LAST:event_mnu_mclearActionPerformed

    private void mni_esaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mni_esaveActionPerformed
        JFileChooser f_chooser = new JFileChooser();
        int status = f_chooser.showSaveDialog(this);
        if (status == JFileChooser.APPROVE_OPTION) {
            File f_filename = f_chooser.getSelectedFile();
            try {
                FileWriter f = new FileWriter(f_filename);
                BufferedWriter w = new BufferedWriter(f);
                for (int i = 0; i < this._pcl_errors.getSize(); i++) {
                    String s = this._pcl_errors.getElementAt(i).toString();
                    w.write(s);
                    w.newLine();
                }
                w.close();
                f.close();
                addError("Log saved to file");
                JOptionPane.showMessageDialog(this, "Log Saved", "Saved", JOptionPane.PLAIN_MESSAGE);
            } catch (Exception e) {
                addError("Error:" + e.toString());
                JOptionPane.showMessageDialog(this, "Could not save the log file:\n" + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Save log cancelled", "Save Log", JOptionPane.PLAIN_MESSAGE);
            return;
        }
    }//GEN-LAST:event_mni_esaveActionPerformed

    private void mni_eclearActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mni_eclearActionPerformed
        this._pcl_errors.clear();
        this._pcl_errors.setUpdate();
    }//GEN-LAST:event_mni_eclearActionPerformed

    private void SaveCharBuff(byte[] b) {
        JFileChooser f_chooser = new JFileChooser();
        int status = f_chooser.showSaveDialog(this);
        if (status == JFileChooser.APPROVE_OPTION) {
            File f_filename = f_chooser.getSelectedFile();
            try {
                FileOutputStream fos = new FileOutputStream(f_filename);
                DataOutputStream dos = new DataOutputStream(fos);
                dos.write(b);
                dos.close();
                fos.close();
                JOptionPane.showMessageDialog(this, "Message Saved", "Saved", JOptionPane.PLAIN_MESSAGE);
            } catch (Exception e) {
            }
        } else {
            JOptionPane.showMessageDialog(this, "Save Message Cancelled", "Save Message", JOptionPane.PLAIN_MESSAGE);
        }
    }
    private void mni_mdexportselectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mni_mdexportselectedActionPerformed
        SaveCharBuff(this.hex_dec.getByteContent());
    }//GEN-LAST:event_mni_mdexportselectedActionPerformed

    private void mni_mcexportselectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mni_mcexportselectedActionPerformed
        SaveCharBuff(this.hex_com.getByteContent());
    }//GEN-LAST:event_mni_mcexportselectedActionPerformed

    private void formComponentResized(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentResized
        this.spn_p_conns.setDividerLocation(200);
        this.spn_messages.setDividerLocation(200);
    }//GEN-LAST:event_formComponentResized

    public static void main(String args[]) {
        java.awt.EventQueue.invokeLater(new Runnable() {

            public void run() {
                new SApCap().setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btn_load;
    private javax.swing.JButton btn_refresh;
    private javax.swing.JButton btn_start;
    private javax.swing.JComboBox cbo_nic;
    private javax.swing.JCheckBox chk_promiscuous;
    private at.HexLib.library.JHexEditor hex_com;
    private at.HexLib.library.JHexEditor hex_dec;
    private at.HexLib.library.JHexEditor hex_params;
    private at.HexLib.library.JHexEditor hex_rfc;
    private at.HexLib.library.JHexEditor hex_vars;
    private at.HexLib.library.JHexEditor hex_verbs;
    private javax.swing.JLabel lbl_d1;
    private javax.swing.JLabel lbl_d2;
    private javax.swing.JLabel lbl_filter;
    private javax.swing.JLabel lbl_nic;
    private javax.swing.JLabel lbl_s1;
    private javax.swing.JLabel lbl_s2;
    private javax.swing.JList lst_cons;
    private javax.swing.JList lst_log;
    private javax.swing.JList lst_messages;
    private javax.swing.JMenuItem mni_csavell;
    private javax.swing.JMenuItem mni_csaveselected;
    private javax.swing.JMenuItem mni_eclear;
    private javax.swing.JMenuItem mni_esave;
    private javax.swing.JMenuItem mni_mcexportselected;
    private javax.swing.JMenuItem mni_mdexportselected;
    private javax.swing.JMenuItem mni_msaveall;
    private javax.swing.JMenuItem mni_msaveselected;
    private javax.swing.JMenuItem mnu_cclear;
    private javax.swing.JPopupMenu mnu_connections;
    private javax.swing.JMenu mnu_csave;
    private javax.swing.JPopupMenu mnu_error;
    private javax.swing.JMenuItem mnu_mclear;
    private javax.swing.JMenu mnu_mcompressed;
    private javax.swing.JMenu mnu_mdecompressed;
    private javax.swing.JPopupMenu mnu_messages;
    private javax.swing.JMenu mnu_mexport;
    private javax.swing.JMenu mnu_msave;
    private javax.swing.JPanel pnl_com;
    private javax.swing.JPanel pnl_config;
    private javax.swing.JPanel pnl_dec;
    private javax.swing.JPanel pnl_log;
    private javax.swing.JPanel pnl_main;
    private javax.swing.JPanel pnl_messages;
    private javax.swing.JPanel pnl_p_conns;
    private javax.swing.JPanel pnl_params;
    private javax.swing.JPanel pnl_rfc;
    private javax.swing.JPanel pnl_themessage;
    private javax.swing.JPanel pnl_themessageoverview;
    private javax.swing.JPanel pnl_vars;
    private javax.swing.JPanel pnl_verbs;
    private javax.swing.JScrollPane scp_messages;
    private javax.swing.JScrollPane spn_log;
    private javax.swing.JSplitPane spn_messages;
    private javax.swing.JSplitPane spn_p_conns;
    private javax.swing.JScrollPane spn_p_cons;
    private javax.swing.JTabbedPane tpn_dec;
    private javax.swing.JTabbedPane tpn_main;
    private javax.swing.JTabbedPane tpn_message;
    private javax.swing.JTextField txt_filter;
    // End of variables declaration//GEN-END:variables
}
