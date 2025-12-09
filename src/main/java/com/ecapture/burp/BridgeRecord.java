package com.ecapture.burp;

import com.ecapture.burp.proto.ECaptureProto;
import java.nio.charset.StandardCharsets;

class BridgeRecord {
    final long timestamp;
    final String uuid;
    final String srcIp;
    final int srcPort;
    final String dstIp;
    final int dstPort;
    final long pid;
    final String pname;
    final String method;
    final String path;
    final String host;
    final String httpVersion;
    final int length;
    final String rawText;
    final byte[] rawBytes;
    final boolean isHttp;
    final String type;
    int statusCode;
    String reason;
    int responseLength;
    byte[] responseBytes;
    String responseText;
    final String hash;

    BridgeRecord(long timestamp, String uuid, String srcIp, int srcPort, String dstIp, int dstPort, long pid, String pname, String method, String path, String host, String httpVersion, int length, String rawText, byte[] rawBytes, boolean isHttp, String type) {
        this.timestamp = timestamp;
        this.uuid = uuid;
        this.srcIp = srcIp;
        this.srcPort = srcPort;
        this.dstIp = dstIp;
        this.dstPort = dstPort;
        this.pid = pid;
        this.pname = pname;
        this.method = method;
        this.path = path;
        this.host = host;
        this.httpVersion = httpVersion;
        this.length = length;
        this.rawText = rawText;
        this.rawBytes = rawBytes;
        this.isHttp = isHttp;
        this.type = type;
        this.hash = sha256Hex(rawBytes);
    }

    static BridgeRecord fromEvent(ECaptureProto.Event evt, byte[] payload) {
        boolean isHttp = isLikelyHttp(payload);
        String line = firstLine(payload);
        String m = methodFromLine(line);
        String p = pathFromLine(line);
        String v = versionFromLine(line);
        String h = hostFromHeaders(payload);
        String text = new String(payload, StandardCharsets.ISO_8859_1);
        if (!isHttp) {
            m = "NON-HTTP";
            v = "RAW";
            p = "";
            h = "";
        }
        String t = mapType(evt.getType(), isHttp);
        return new BridgeRecord(
                evt.getTimestamp(),
                evt.getUuid(),
                evt.getSrcIp(),
                evt.getSrcPort(),
                evt.getDstIp(),
                evt.getDstPort(),
                evt.getPid(),
                evt.getPname(),
                m,
                p,
                h,
                v,
                payload.length,
                text,
                payload,
                isHttp,
                t
        );
    }

    private static String firstLine(byte[] data) {
        int i = 0;
        while (i < data.length - 1) {
            if (data[i] == '\r' && data[i + 1] == '\n') break;
            i++;
        }
        return new String(data, 0, Math.min(i + 2, data.length), StandardCharsets.US_ASCII);
    }

    private static String methodFromLine(String line) {
        int i = line.indexOf(' ');
        if (i <= 0) return "";
        return line.substring(0, i);
    }

    private static String pathFromLine(String line) {
        int first = line.indexOf(' ');
        if (first < 0) return "";
        int second = line.indexOf(' ', first + 1);
        if (second < 0) return line.substring(first + 1).trim();
        return line.substring(first + 1, second).trim();
    }

    private static String versionFromLine(String line) {
        int first = line.indexOf(' ');
        if (first < 0) return "";
        int second = line.indexOf(' ', first + 1);
        if (second < 0) return "";
        return line.substring(second + 1).trim();
    }

    private static String hostFromHeaders(byte[] data) {
        int i = 0;
        int end = data.length;
        while (i < end - 1) {
            int lineStart = i;
            while (i < end - 1 && !(data[i] == '\r' && data[i + 1] == '\n')) i++;
            int lineEnd = i;
            String line = new String(data, lineStart, lineEnd - lineStart, StandardCharsets.US_ASCII);
            if (line.isEmpty()) break;
            if (line.regionMatches(true, 0, "Host:", 0, 5)) {
                String v = line.substring(5).trim();
                return v;
            }
            i = Math.min(end, i + 2);
        }
        return "";
    }

    static String sha256Hex(byte[] data) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(data);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean isLikelyHttp(byte[] data) {
        if (data == null || data.length < 4) return false;
        String s = new String(data, 0, Math.min(data.length, 16), StandardCharsets.US_ASCII).toUpperCase();
        return s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("PUT ") || s.startsWith("DELETE ") || s.startsWith("HEAD ") || s.startsWith("OPTIONS ") || s.startsWith("CONNECT ");
    }

    private static String mapType(int t, boolean isHttp) {
        if (isHttp) return "HTTP";
        switch (t) {
            case 2: return "TLS";
            case 3: return "HTTP2-Frame";
            case 4: return "MQTT";
            case 5: return "DNS";
            case 6: return "MySQL";
            case 7: return "Redis";
            case 8: return "PostgreSQL";
            case 9: return "MongoDB";
            case 10: return "WebSocket";
            case 11: return "QUIC";
            default:
                return "RAW";
        }
    }
}
