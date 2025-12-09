package com.ecapture.burp;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.BorderFactory;
import javax.swing.border.LineBorder;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.Color;
import java.awt.Graphics;
import javax.swing.Icon;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import javax.swing.JTabbedPane;
import javax.swing.RowFilter;
import javax.swing.table.TableRowSorter;
import javax.swing.JFileChooser;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

class BridgePanel extends JPanel {
    private final ECaptureBridge bridge;
    private final JTextField wsField;
    private final JTextField proxyHostField;
    private final JTextField proxyPortField;
    private final JButton connectBtn;
    private final JButton disconnectBtn;
    private final JCheckBox autoReconnectBox;
    private final JLabel statusLabel;
    private final DotIcon statusDot;
    private final JLabel totalLabel;
    private final JLabel httpLabel;
    private final JLabel nonHttpLabel;
    private final HistoryTableModel tableModel;
    private final JTable table;
    private final RawEditor rawEditor;
    private final HttpRequestEditor httpEditor;
    private final HttpResponseEditor responseEditor;
    private final JTextField searchField;
    private final JTextField methodFilterField;
    private final JTextField hostFilterField;
    private final JTextField statusFilterField;
    private final JTextField maxHistoryField;
    private final JTextField maxRetryField;
    private final JButton exportAllBtn;
    private final JButton exportSelBtn;
    private final JButton retryBtn;

    BridgePanel(ECaptureBridge bridge, RawEditor rawEditor, HttpRequestEditor httpEditor, HttpResponseEditor responseEditor) {
        this.bridge = bridge;
        this.rawEditor = rawEditor;
        this.httpEditor = httpEditor;
        this.responseEditor = responseEditor;
        setLayout(new BorderLayout());
        JPanel top = new JPanel(new GridBagLayout());
        top.setBorder(new EmptyBorder(8, 8, 8, 8));
        wsField = new JTextField("ws://127.0.0.1:28257/", 24);
        proxyHostField = new JTextField("127.0.0.1", 12);
        proxyPortField = new JTextField("8080", 6);
        connectBtn = new JButton("Connect");
        disconnectBtn = new JButton("Disconnect");
        autoReconnectBox = new JCheckBox("Auto Reconnect", true);
        statusDot = new DotIcon(new Color(0xD93025));
        statusLabel = new JLabel("未连接");
        statusLabel.setOpaque(false);
        statusLabel.setForeground(new Color(0x212121));
        statusLabel.setIcon(statusDot);
        statusLabel.setIconTextGap(6);
        statusLabel.setBorder(BorderFactory.createCompoundBorder(new LineBorder(new Color(0xBDBDBD), 1, true), new EmptyBorder(2, 8, 2, 8)));
        totalLabel = new JLabel("总数 0");
        totalLabel.setBorder(BorderFactory.createCompoundBorder(new LineBorder(new Color(0xBDBDBD), 1, true), new EmptyBorder(2, 8, 2, 8)));
        httpLabel = new JLabel("HTTP 0");
        httpLabel.setBorder(BorderFactory.createCompoundBorder(new LineBorder(new Color(0xBDBDBD), 1, true), new EmptyBorder(2, 8, 2, 8)));
        nonHttpLabel = new JLabel("非HTTP 0");
        nonHttpLabel.setBorder(BorderFactory.createCompoundBorder(new LineBorder(new Color(0xBDBDBD), 1, true), new EmptyBorder(2, 8, 2, 8)));
        searchField = new JTextField("", 18);
        methodFilterField = new JTextField("", 8);
        hostFilterField = new JTextField("", 14);
        statusFilterField = new JTextField("", 6);
        maxHistoryField = new JTextField("500", 5);
        maxRetryField = new JTextField("10", 4);
        retryBtn = new JButton("Retry");
        GridBagConstraints gbc;

        gbc = new GridBagConstraints();
        gbc.gridx = 0; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4); gbc.anchor = GridBagConstraints.WEST;
        top.add(new JLabel("WebSocket"), gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.insets = new Insets(4,4,4,4);
        top.add(wsField, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 2; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(new JLabel("Proxy Host"), gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 3; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4); gbc.fill = GridBagConstraints.HORIZONTAL;
        top.add(proxyHostField, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 4; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(new JLabel("Port"), gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 5; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4); gbc.fill = GridBagConstraints.HORIZONTAL;
        top.add(proxyPortField, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 6; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(connectBtn, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 7; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(disconnectBtn, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 8; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(autoReconnectBox, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 9; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(new JLabel("Max Retry"), gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 10; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4); gbc.fill = GridBagConstraints.HORIZONTAL;
        top.add(maxRetryField, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 11; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(retryBtn, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 12; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(new JLabel("Max History"), gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 13; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4); gbc.fill = GridBagConstraints.HORIZONTAL;
        top.add(maxHistoryField, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 14; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(totalLabel, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 15; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(httpLabel, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 16; gbc.gridy = 0; gbc.insets = new Insets(4,4,4,4);
        top.add(nonHttpLabel, gbc);

        gbc = new GridBagConstraints();
        gbc.gridx = 0; gbc.gridy = 1; gbc.insets = new Insets(4,4,4,4); gbc.anchor = GridBagConstraints.WEST;
        top.add(new JLabel("Search"), gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.insets = new Insets(4,4,4,4);
        top.add(searchField, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 2; gbc.gridy = 1; gbc.insets = new Insets(4,4,4,4);
        top.add(new JLabel("Method"), gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 3; gbc.gridy = 1; gbc.insets = new Insets(4,4,4,4); gbc.fill = GridBagConstraints.HORIZONTAL;
        top.add(methodFilterField, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 4; gbc.gridy = 1; gbc.insets = new Insets(4,4,4,4);
        top.add(new JLabel("Host"), gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 5; gbc.gridy = 1; gbc.insets = new Insets(4,4,4,4); gbc.fill = GridBagConstraints.HORIZONTAL;
        top.add(hostFilterField, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 6; gbc.gridy = 1; gbc.insets = new Insets(4,4,4,4);
        top.add(new JLabel("Status"), gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 7; gbc.gridy = 1; gbc.insets = new Insets(4,4,4,4); gbc.fill = GridBagConstraints.HORIZONTAL;
        top.add(statusFilterField, gbc);
        gbc = new GridBagConstraints();
        gbc.gridx = 8; gbc.gridy = 1; gbc.insets = new Insets(4,4,4,4);
        top.add(statusLabel, gbc);
        add(top, BorderLayout.NORTH);

        tableModel = new HistoryTableModel();
        table = new JTable(tableModel);
        TableRowSorter<HistoryTableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        table.setPreferredScrollableViewportSize(new Dimension(600, 300));
        JScrollPane tableScroll = new JScrollPane(table);
        Component reqView = httpEditor.uiComponent();
        Component respView = responseEditor.uiComponent();
        JSplitPane rightSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqView, respView);
        rightSplit.setResizeWeight(0.5);
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, rightSplit);
        mainSplit.setResizeWeight(0.55);
        add(mainSplit, BorderLayout.CENTER);

        connectBtn.addActionListener(e -> {
            String ws = wsField.getText().trim();
            String host = proxyHostField.getText().trim();
            int port = parsePort(proxyPortField.getText().trim());
            bridge.updateConfig(ws, host, port);
            bridge.setAutoReconnect(autoReconnectBox.isSelected());
            bridge.setMaxReconnectAttempts(parsePort(maxRetryField.getText().trim()));
            bridge.connect();
            persist();
        });
        disconnectBtn.addActionListener(e -> bridge.disconnect());
        autoReconnectBox.addActionListener(e -> { bridge.setAutoReconnect(autoReconnectBox.isSelected()); persist(); });
        retryBtn.addActionListener(e -> bridge.retryConnect());
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
        });
        methodFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
        });
        hostFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
        });
        statusFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilter(sorter); persist(); }
        });
        maxHistoryField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateMaxHistory(); persist(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateMaxHistory(); persist(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateMaxHistory(); persist(); }
        });
        exportAllBtn = new JButton("Export All");
        exportSelBtn = new JButton("Export Selected");
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        bottomBar.add(exportSelBtn);
        bottomBar.add(exportAllBtn);
        add(bottomBar, BorderLayout.SOUTH);
        exportSelBtn.addActionListener(e -> exportSelected());
        exportAllBtn.addActionListener(e -> exportAll());
        table.getSelectionModel().addListSelectionListener(e -> {
            int i = table.getSelectedRow();
            if (i >= 0) {
                BridgeRecord r = tableModel.get(table.convertRowIndexToModel(i));
                rawEditor.setContents(burp.api.montoya.core.ByteArray.byteArray(r.rawBytes));
                rawEditor.setCaretPosition(0);
                if (r.isHttp) {
                    httpEditor.setRequest(burp.api.montoya.http.message.requests.HttpRequest.httpRequest(burp.api.montoya.core.ByteArray.byteArray(r.rawBytes)));
                    if (r.responseBytes != null) {
                        responseEditor.setResponse(burp.api.montoya.http.message.responses.HttpResponse.httpResponse(burp.api.montoya.core.ByteArray.byteArray(r.responseBytes)));
                    }
                }
            }
        });
    }

    void setConnected(boolean b) {
        SwingUtilities.invokeLater(() -> {
            connectBtn.setEnabled(!b);
            disconnectBtn.setEnabled(b);
        });
    }

    void addRecord(BridgeRecord r) {
        SwingUtilities.invokeLater(() -> {
            tableModel.add(r);
            int i = tableModel.getRowCount() - 1;
            if (i >= 0) {
                int viewIdx = table.convertRowIndexToView(i);
                if (viewIdx >= 0) table.setRowSelectionInterval(viewIdx, viewIdx);
            }
            updateCounters();
        });
    }

    

    private int parsePort(String s) {
        try {
            return Integer.parseInt(s);
        } catch (Exception e) {
            return 8080;
        }
    }

    void setStatus(String s) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(s);
            updateStatusStyle(s);
        });
    }

    private void updateStatusStyle(String s) {
        String v = s == null ? "" : s.trim().toLowerCase();
        if (v.equals("connected")) {
            statusLabel.setText("已连接");
            statusDot.setColor(new Color(0x34A853));
            statusLabel.setBorder(BorderFactory.createCompoundBorder(new LineBorder(new Color(0xA5D6A7), 1, true), new EmptyBorder(2, 8, 2, 8)));
            return;
        }
        if (v.equals("connecting") || v.startsWith("reconnecting")) {
            statusLabel.setText("连接中…");
            statusDot.setColor(new Color(0xF4B400));
            statusLabel.setBorder(BorderFactory.createCompoundBorder(new LineBorder(new Color(0xFFE082), 1, true), new EmptyBorder(2, 8, 2, 8)));
            return;
        }
        statusLabel.setText("未连接");
        statusDot.setColor(new Color(0xD93025));
        statusLabel.setBorder(BorderFactory.createCompoundBorder(new LineBorder(new Color(0xFFCDD2), 1, true), new EmptyBorder(2, 8, 2, 8)));
    }

    private void updateCounters() {
        int total = tableModel.getRowCount();
        int http = 0;
        for (BridgeRecord r : tableModel.getAll()) {
            if (r.isHttp) http++;
        }
        int nonHttp = Math.max(0, total - http);
        totalLabel.setText("总数 " + total);
        httpLabel.setText("HTTP " + http);
        nonHttpLabel.setText("非HTTP " + nonHttp);
    }

    private static class DotIcon implements Icon {
        private Color color;
        private final int size = 8;
        DotIcon(Color c) { this.color = c; }
        void setColor(Color c) { this.color = c; }
        @Override public int getIconWidth() { return size; }
        @Override public int getIconHeight() { return size; }
        @Override public void paintIcon(Component c, Graphics g, int x, int y) {
            g.setColor(color);
            g.fillOval(x, y, size, size);
            g.setColor(color.darker());
            g.drawOval(x, y, size, size);
        }
    }

    private void applyFilter(TableRowSorter<HistoryTableModel> sorter) {
        String q = searchField.getText().trim().toLowerCase();
        String mf = methodFilterField.getText().trim().toLowerCase();
        String hf = hostFilterField.getText().trim().toLowerCase();
        String sf = statusFilterField.getText().trim();
        if (q.isEmpty()) {
            sorter.setRowFilter(new RowFilter<HistoryTableModel, Integer>() {
                public boolean include(Entry<? extends HistoryTableModel, ? extends Integer> entry) {
                    return matchAdvanced(entry, mf, hf, sf);
                }
            });
            return;
        }
        sorter.setRowFilter(new RowFilter<HistoryTableModel, Integer>() {
            public boolean include(Entry<? extends HistoryTableModel, ? extends Integer> entry) {
                for (int c = 0; c < entry.getValueCount(); c++) {
                    Object v = entry.getValue(c);
                    if (v != null && v.toString().toLowerCase().contains(q)) return true;
                }
                return matchAdvanced(entry, mf, hf, sf);
            }
        });
    }

    private boolean matchAdvanced(RowFilter.Entry<? extends HistoryTableModel, ? extends Integer> entry, String mf, String hf, String sf) {
        boolean ok = true;
        if (!mf.isEmpty()) ok &= entry.getValue(3).toString().toLowerCase().contains(mf);
        if (!hf.isEmpty()) ok &= entry.getValue(5).toString().toLowerCase().contains(hf);
        if (!sf.isEmpty()) ok &= entry.getValue(8).toString().contains(sf);
        return ok;
    }

    void updateMaxHistory() {
        int v = parsePort(maxHistoryField.getText().trim());
        tableModel.setMaxSize(Math.max(1, v));
    }

    private void exportSelected() {
        int i = table.getSelectedRow();
        if (i < 0) return;
        BridgeRecord r = tableModel.get(table.convertRowIndexToModel(i));
        JFileChooser ch = new JFileChooser();
        ch.setSelectedFile(new File("ecapture-bridge-selected.txt"));
        if (ch.showSaveDialog(this) == javax.swing.JFileChooser.APPROVE_OPTION) {
            File f = ch.getSelectedFile();
            try (FileOutputStream os = new FileOutputStream(f)) {
                os.write(r.rawBytes);
                if (r.responseBytes != null) {
                    os.write("\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
                    os.write(r.responseBytes);
                }
            } catch (Exception ignored) {}
        }
    }

    private void exportAll() {
        JFileChooser ch = new JFileChooser();
        ch.setSelectedFile(new File("ecapture-bridge-all.txt"));
        if (ch.showSaveDialog(this) == javax.swing.JFileChooser.APPROVE_OPTION) {
            File f = ch.getSelectedFile();
            try (FileOutputStream os = new FileOutputStream(f)) {
                for (BridgeRecord r : tableModel.getAll()) {
                    os.write(r.rawBytes);
                    os.write("\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
                    if (r.responseBytes != null) os.write(r.responseBytes);
                    os.write("\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
                }
            } catch (Exception ignored) {}
        }
    }

    void setInitialValues(String ws, String host, int port, boolean auto, int maxRetry, int maxHistory, String search, String methodFilter, String hostFilter, String statusFilter) {
        wsField.setText(ws);
        proxyHostField.setText(host);
        proxyPortField.setText(String.valueOf(port));
        autoReconnectBox.setSelected(auto);
        maxRetryField.setText(String.valueOf(maxRetry));
        maxHistoryField.setText(String.valueOf(maxHistory));
        searchField.setText(search == null ? "" : search);
        methodFilterField.setText(methodFilter == null ? "" : methodFilter);
        hostFilterField.setText(hostFilter == null ? "" : hostFilter);
        statusFilterField.setText(statusFilter == null ? "" : statusFilter);
    }

    void refreshRecord(BridgeRecord r) {
        int idx = tableModel.indexOfByHash(r.hash);
        if (idx >= 0) {
            tableModel.updateRow(idx);
            int viewIdx = table.convertRowIndexToView(idx);
            if (viewIdx >= 0) {
                table.setRowSelectionInterval(viewIdx, viewIdx);
                rawEditor.setContents(burp.api.montoya.core.ByteArray.byteArray(r.rawBytes));
                httpEditor.setRequest(burp.api.montoya.http.message.requests.HttpRequest.httpRequest(burp.api.montoya.core.ByteArray.byteArray(r.rawBytes)));
                if (r.responseBytes != null) {
                    responseEditor.setResponse(burp.api.montoya.http.message.responses.HttpResponse.httpResponse(burp.api.montoya.core.ByteArray.byteArray(r.responseBytes)));
                }
            }
        }
    }

    private void persist() {
        String ws = wsField.getText().trim();
        String host = proxyHostField.getText().trim();
        int port = parsePort(proxyPortField.getText().trim());
        boolean auto = autoReconnectBox.isSelected();
        int maxRetry = parsePort(maxRetryField.getText().trim());
        int maxHistory = parsePort(maxHistoryField.getText().trim());
        String search = searchField.getText().trim();
        String mf = methodFilterField.getText().trim();
        String hf = hostFilterField.getText().trim();
        String sf = statusFilterField.getText().trim();
        bridge.savePrefs(ws, host, port, auto, maxRetry, maxHistory, search, mf, hf, sf);
    }
}
