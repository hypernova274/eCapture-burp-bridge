package com.ecapture.burp;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

class HistoryTableModel extends AbstractTableModel {
    private final String[] cols = new String[]{"Index", "Time", "Method", "Path", "Host", "HTTP", "Type", "Status", "Length", "Proc", "UUID"};
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
                return rowIndex + 1;
            case 1:
                return formatTime(r.timestamp);
            case 2:
                return r.method;
            case 3:
                return r.path;
            case 4:
                return r.host;
            case 5:
                return r.httpVersion;
            case 6:
                return r.type;
            case 7:
                return r.statusCode;
            case 8:
                return r.length;
            case 9:
                return r.pname + "(" + r.pid + ")";
            case 10:
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

    void clear() {
        rows.clear();
        fireTableDataChanged();
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

    private String formatTime(long ts) {
        ZoneId zone = ZoneId.systemDefault();
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        long nowNs = System.nanoTime();
        long nowMs = System.currentTimeMillis();
        if (ts >= 1_000_000_000_000_000L) {
            long s = ts / 1_000_000_000L;
            int nanos = (int) (ts % 1_000_000_000L);
            LocalDateTime ldt = LocalDateTime.ofInstant(Instant.ofEpochSecond(s, nanos), zone);
            int y = ldt.getYear();
            if (y < 2000 || y > 2100) {
                long ms = nowMs + (ts - nowNs) / 1_000_000L;
                return fmt.format(Instant.ofEpochMilli(ms).atZone(zone));
            }
            return fmt.format(ldt);
        }
        if (ts >= 1_000_000_000_000L) {
            long s = ts / 1_000_000L;
            int nanos = (int) ((ts % 1_000_000L) * 1_000L);
            return fmt.format(Instant.ofEpochSecond(s, nanos).atZone(zone));
        }
        if (ts >= 1_000_000_000L) {
            return fmt.format(Instant.ofEpochMilli(ts).atZone(zone));
        }
        return fmt.format(Instant.ofEpochSecond(ts).atZone(zone));
    }
}
