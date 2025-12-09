package com.ecapture.burp;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

class HistoryTableModel extends AbstractTableModel {
    private final String[] cols = new String[]{"Time", "Src", "Dst", "Method", "Path", "Host", "HTTP", "Type", "Status", "Length", "Proc", "UUID"};
    private final List<BridgeRecord> rows = new ArrayList<>();
    private int maxSize = 500;

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return cols.length;
    }

    @Override
    public String getColumnName(int column) {
        return cols[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        BridgeRecord r = rows.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return r.timestamp;
            case 1:
                return r.srcIp + ":" + r.srcPort;
            case 2:
                return r.dstIp + ":" + r.dstPort;
            case 3:
                return r.method;
            case 4:
                return r.path;
            case 5:
                return r.host;
            case 6:
                return r.httpVersion;
            case 7:
                return r.type;
            case 8:
                return r.statusCode;
            case 9:
                return r.length;
            case 10:
                return r.pname + "(" + r.pid + ")";
            case 11:
                return r.uuid;
            default:
                return "";
        }
    }

    void add(BridgeRecord r) {
        rows.add(r);
        int i = rows.size() - 1;
        fireTableRowsInserted(i, i);
        trimIfNeeded();
    }

    BridgeRecord get(int i) {
        return rows.get(i);
    }

    void setMaxSize(int size) {
        this.maxSize = size;
        trimIfNeeded();
    }

    List<BridgeRecord> getAll() {
        return new ArrayList<>(rows);
    }

    private void trimIfNeeded() {
        while (rows.size() > maxSize) {
            rows.remove(0);
            fireTableRowsDeleted(0, 0);
        }
    }

    int indexOfByHash(String hash) {
        for (int i = 0; i < rows.size(); i++) {
            BridgeRecord r = rows.get(i);
            if (r.hash.equals(hash)) return i;
        }
        return -1;
    }

    void updateRow(int idx) {
        if (idx >= 0 && idx < rows.size()) fireTableRowsUpdated(idx, idx);
    }
}
