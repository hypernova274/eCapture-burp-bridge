package com.ecapture.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;
import static burp.api.montoya.core.ByteArray.byteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.ecapture.burp.proto.ECaptureProto;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.java_websocket.drafts.Draft_6455;

import javax.swing.SwingUtilities;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class ECaptureBridge implements BurpExtension {
    private MontoyaApi api;
    private Logging logging;
    private BridgePanel panel;
    private RawEditor requestEditor;
    private HttpRequestEditor httpEditor;
    private HttpResponseEditor responseEditor;
    private volatile ECaptureClient client;
    private String wsUrl = "ws://127.0.0.1:28257/";
    private String proxyHost = "127.0.0.1";
    private int proxyPort = 8080;
    private boolean autoReconnect = true;
    private java.util.concurrent.ScheduledExecutorService scheduler;
    private int reconnectAttempts = 0;
    private int maxReconnectAttempts = 10;
    private final java.util.concurrent.ConcurrentHashMap<String, BridgeRecord> recordsByHash = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<Integer, String> idsToHash = new java.util.concurrent.ConcurrentHashMap<>();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        api.extension().setName("eCapture Bridge");
        UserInterface ui = api.userInterface();
        requestEditor = ui.createRawEditor();
        httpEditor = ui.createHttpRequestEditor();
        responseEditor = ui.createHttpResponseEditor();
        this.panel = new BridgePanel(this, requestEditor, httpEditor, responseEditor);
        ui.applyThemeToComponent(panel);
        ui.registerSuiteTab("eCapture Bridge", panel);
        scheduler = java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
        loadPrefs();
        api.http().registerHttpHandler(new BridgeHttpHandler());
        panel.setConnected(false);
        panel.setStatus("Idle");
    }

    void connect() {
        try {
            ECaptureClient c = new ECaptureClient(new URI(wsUrl), buildWsHeaders());
            c.connect();
            client = c;
            panel.setConnected(true);
            logging.logToOutput("WebSocket connecting: " + wsUrl);
            panel.setStatus("Connecting");
            reconnectAttempts = 0;
        } catch (Exception e) {
            logging.logToError(e.getMessage());
            scheduleReconnect();
        }
    }

    void disconnect() {
        ECaptureClient c = client;
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
            }
            client = null;
            panel.setConnected(false);
            panel.setStatus("Disconnected");
        }
    }

    void updateConfig(String ws, String host, int port) {
        this.wsUrl = ws;
        this.proxyHost = host;
        this.proxyPort = port;
    }

    void forwardToBurp(byte[] data, ECaptureProto.Event evt) {
        boolean http = isHttpRequest(data);
        try {
            if (http) {
                Socket s = new Socket();
                s.connect(new InetSocketAddress(proxyHost, proxyPort), 3000);
                s.getOutputStream().write(data);
                s.getOutputStream().flush();
                s.close();
            }
            BridgeRecord r = BridgeRecord.fromEvent(evt, data);
            panel.addRecord(r);
            requestEditor.setContents(byteArray(r.rawBytes));
            if (http) {
                HttpRequest req = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(byteArray(r.rawBytes));
                httpEditor.setRequest(req);
                recordsByHash.put(r.hash, r);
            }
        } catch (Exception e) {
            logging.logToError(e.getMessage());
        }
    }

    boolean isHttpRequest(byte[] data) {
        if (data == null || data.length < 4) return false;
        String s = new String(data, 0, Math.min(data.length, 16), StandardCharsets.US_ASCII).toUpperCase();
        return s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("PUT ") || s.startsWith("DELETE ") || s.startsWith("HEAD ") || s.startsWith("OPTIONS ") || s.startsWith("CONNECT ");
    }

    class ECaptureClient extends WebSocketClient {
        ECaptureClient(URI uri) {
            super(uri);
        }

        ECaptureClient(URI uri, Map<String, String> headers) {
            super(uri, new Draft_6455(), headers, 0);
        }

        @Override
        public void onOpen(ServerHandshake handsh) {
            logging.logToOutput("WebSocket connected");
            panel.setConnected(true);
            panel.setStatus("Connected");
        }

        @Override
        public void onMessage(String message) {
        }

        @Override
        public void onMessage(ByteBuffer bytes) {
            try {
                byte[] data = new byte[bytes.remaining()];
                bytes.get(data);
                ECaptureProto.LogEntry entry = ECaptureProto.LogEntry.parseFrom(data);
                ECaptureProto.LogType logType = entry.getLogType();
                if (logType == ECaptureProto.LogType.LOG_TYPE_HEARTBEAT) {
                    return;
                }
                if (logType == ECaptureProto.LogType.LOG_TYPE_PROCESS_LOG) {
                    return;
                }
                if (logType == ECaptureProto.LogType.LOG_TYPE_EVENT) {
                    if (entry.hasEventPayload()) {
                        ECaptureProto.Event evt = entry.getEventPayload();
                        byte[] payload = evt.getPayload().toByteArray();
                        if (payload.length > 0) {
                            logging.logToOutput("Forwarding event payload: " + payload.length + " bytes");
                            forwardToBurp(payload, evt);
                        } else {
                            logging.logToOutput("Event payload empty");
                        }
                    } else {
                        logging.logToOutput("Event without payload");
                    }
                } else {
                    logging.logToOutput("Unknown log type: " + logType.name());
                }
            } catch (com.google.protobuf.InvalidProtocolBufferException e) {
                logging.logToError("Protobuf parse error: " + e.getMessage());
            } catch (Exception e) {
                logging.logToError("onMessage error: " + e.toString());
            }
        }

        @Override
        public void onClose(int code, String reason, boolean remote) {
            logging.logToOutput("WebSocket closed: " + reason);
            SwingUtilities.invokeLater(() -> panel.setConnected(false));
            panel.setStatus("Closed");
            if (remote) {
                scheduleReconnect();
            }
        }

        @Override
        public void onError(Exception ex) {
            logging.logToError(ex.getMessage());
            panel.setStatus("Error");
            scheduleReconnect();
        }
    }

    private Map<String, String> buildWsHeaders() {
        Map<String, String> h = new HashMap<>();
        h.put("Origin", computeOrigin(wsUrl));
        return h;
    }

    private String computeOrigin(String ws) {
        try {
            URI u = new URI(ws);
            String scheme = u.getScheme();
            String originScheme = "http";
            if ("wss".equalsIgnoreCase(scheme)) originScheme = "https";
            int port = u.getPort();
            String host = u.getHost();
            if (host == null) host = "127.0.0.1";
            if (port > 0) {
                return originScheme + "://" + host + ":" + port;
            }
            return originScheme + "://" + host;
        } catch (Exception e) {
            return "http://127.0.0.1";
        }
    }

    void setAutoReconnect(boolean b) {
        autoReconnect = b;
    }

    void setMaxReconnectAttempts(int max) {
        maxReconnectAttempts = Math.max(0, max);
    }

    void retryConnect() {
        disconnect();
        connect();
    }

    private void scheduleReconnect() {
        if (!autoReconnect) return;
        if (client != null) return;
        reconnectAttempts++;
        if (reconnectAttempts > maxReconnectAttempts) return;
        long delay = Math.min(30000, (long) (2000 * Math.pow(2, Math.min(reconnectAttempts, 5))));
        panel.setStatus("Reconnecting in " + (delay / 1000) + "s");
        scheduler.schedule(this::connect, delay, java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    void savePrefs(String ws, String host, int port, boolean auto, int maxRetry, int maxHistory, String search, String methodFilter, String hostFilter, String statusFilter) {
        var p = api.persistence().preferences();
        p.setString("ecapture.ws", ws);
        p.setString("ecapture.proxy.host", host);
        p.setString("ecapture.proxy.port", String.valueOf(port));
        p.setString("ecapture.autoReconnect", String.valueOf(auto));
        p.setString("ecapture.maxRetry", String.valueOf(maxRetry));
        p.setString("ecapture.maxHistory", String.valueOf(maxHistory));
        p.setString("ecapture.search", search == null ? "" : search);
        p.setString("ecapture.filter.method", methodFilter == null ? "" : methodFilter);
        p.setString("ecapture.filter.host", hostFilter == null ? "" : hostFilter);
        p.setString("ecapture.filter.status", statusFilter == null ? "" : statusFilter);
    }

    private void loadPrefs() {
        var p = api.persistence().preferences();
        String ws = def(p.getString("ecapture.ws"), wsUrl);
        String host = def(p.getString("ecapture.proxy.host"), proxyHost);
        int port = parseInt(def(p.getString("ecapture.proxy.port"), String.valueOf(proxyPort)), proxyPort);
        boolean auto = Boolean.parseBoolean(def(p.getString("ecapture.autoReconnect"), String.valueOf(autoReconnect)));
        int maxRetry = parseInt(def(p.getString("ecapture.maxRetry"), String.valueOf(maxReconnectAttempts)), maxReconnectAttempts);
        int maxHistory = parseInt(def(p.getString("ecapture.maxHistory"), "500"), 500);
        String search = def(p.getString("ecapture.search"), "");
        String mf = def(p.getString("ecapture.filter.method"), "");
        String hf = def(p.getString("ecapture.filter.host"), "");
        String sf = def(p.getString("ecapture.filter.status"), "");
        updateConfig(ws, host, port);
        setAutoReconnect(auto);
        setMaxReconnectAttempts(maxRetry);
        panel.setInitialValues(ws, host, port, auto, maxRetry, maxHistory, search, mf, hf, sf);
        panel.updateMaxHistory();
    }

    private String def(String v, String d) {
        return v == null || v.isEmpty() ? d : v;
    }

    private int parseInt(String s, int d) {
        try { return Integer.parseInt(s); } catch (Exception e) { return d; }
    }

    class BridgeHttpHandler implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            try {
                byte[] rb = request.toByteArray().getBytes();
                String h = BridgeRecord.sha256Hex(rb);
                if (recordsByHash.containsKey(h)) {
                    idsToHash.put(request.messageId(), h);
                }
            } catch (Exception ignored) {
            }
            return RequestToBeSentAction.continueWith(request);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseEvent) {
            try {
                String h = idsToHash.remove(responseEvent.messageId());
                if (h != null) {
                    BridgeRecord r = recordsByHash.get(h);
                    if (r != null) {
                        byte[] respBytes = responseEvent.toByteArray().getBytes();
                        r.statusCode = responseEvent.statusCode();
                        r.reason = responseEvent.reasonPhrase();
                        r.responseBytes = respBytes;
                        r.responseLength = respBytes.length;
                        r.responseText = responseEvent.toString();
                        panel.refreshRecord(r);
                    }
                }
            } catch (Exception ignored) {
            }
            return ResponseReceivedAction.continueWith(responseEvent);
        }
    }
}
