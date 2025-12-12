English | [中文](README_zh.md)

# eCapture-burp-bridge

A Burp Suite extension that connects to local eCapture: a WebSocket client receives a Protobuf event stream, extracts raw HTTP messages and transparently forwards them to Burp Proxy, while ingesting all events (including non-HTTP) to help debug and analyze mobile/app network traffic.

## Features
- Connect to local eCapture (`ws://`/`wss://`), auto-set the `Origin` header to avoid CSWSH 403 rejections
- Parse Protobuf `LogEntry`, ignore heartbeat/runtime logs, only handle `Event`
- Transparently forward HTTP requests to Burp Proxy (friendly to Invisible Proxy mode)
- Persist all events in the table: unified view for HTTP and non-HTTP; non-HTTP uses `Method=NON-HTTP`, `HTTP=RAW` and marks `Type`
- Live counters: `Total`, `HTTP`, `Non-HTTP`
- Search/filter (method, host, status code) and one-click export selected/all
- Auto reconnect (exponential backoff) with visual connection status

## Architecture
- Source: eCapture outputs Protobuf events at `ws://127.0.0.1:28257/`
- Bridge: WebSocket client connect → parse `Event` → detect HTTP → forward to Burp (HTTP only) → persist all events into table
- Destination: Burp Proxy (e.g., `127.0.0.1:28887`), enable Invisible Proxy

## Requirements
- Java 21
- Gradle 8.x
- Burp Suite (Montoya API 2025.11 support)

## Build
```powershell
# In project root
.\gradlew.bat shadowJar
# Generated extension JAR:
# build\libs\eCapture-Bridge-0.1.0.jar
```

## Install & Use
1. Open Burp → Extender → Extensions → Add → choose `build\libs\eCapture-Bridge-0.1.0.jar`
2. Connect your phone and set ADB port forwarding: ```bash adb forward tcp:28257 tcp:28257```
3. Start eCapture (enable the WebSocket service):
# Replace <PID> with the target app PID
```./ecapture tls -p <PID> --ecaptureq=ws://0.0.0.0:28257/```
4. Switch to the "eCapture Bridge" tab and fill in:
   - `WebSocket`: eCapture address (e.g., `ws://127.0.0.1:28257/`)
   - `Proxy Host`: Burp proxy host (default `127.0.0.1`)
   - `Port`: Burp proxy port (e.g., `28887`)
5. Click `Connect`; the status shows “connecting” → “connected” when successful
6. Once there is network traffic, the table panel displays events; selecting a row:
   - HTTP: request/response shown at the bottom
   - Non-HTTP: raw bytes shown at the bottom

<img width="2560" height="1200" alt="image-20251210015217178" src="https://github.com/user-attachments/assets/ce70f1ce-0f26-416a-b799-f03541fe7ac0" />

<img src="https://github.com/user-attachments/assets/726e75bf-cdc8-4029-80e5-36965830a2cd" width="60%" alt="eCapture bridge interface main" />


## UI Overview

<img width="2554" height="1199" alt="image-20251210012109599" src="https://github.com/user-attachments/assets/39d26ad6-8e69-4ce6-8ee9-a967d388971b" />

- Top bar: connect/disconnect, auto-reconnect, retry count, max history, search/filter input
- Status badges: Not connected / Connecting… / Connected / Closed / Error
- Counter badges: `Total N`, `HTTP H`, `Non-HTTP NH`
- Table columns: `Time, Src, Dst, Method, Path, Host, HTTP, Type, Status, Length, Proc, UUID`
- Export: export selected or all events to a text file

## Technical Details
- WebSocket: uses Java-WebSocket; during handshake, computes `Origin: http://host:port` / `https://host:port` according to `ws://`/`wss://`
- Protobuf: parses `LogEntry`, only processes `LOG_TYPE_EVENT`; heartbeat and runtime logs are ignored
- HTTP detection: prefix match `GET/POST/PUT/DELETE/HEAD/OPTIONS/CONNECT`
- Non-HTTP marking: `Method=NON-HTTP`, `HTTP=RAW`, `Path/Host` cleared, and `Type` mapped from `Event.type` (e.g., `TLS`, `HTTP2-Frame`, `MQTT`, `DNS`, `MySQL`, `Redis`, `PostgreSQL`, `MongoDB`, `WebSocket`, `QUIC`, `RAW`)
- Response correlation: associate by request-bytes hash with Burp MessageId, backfill `Status/Response` and refresh the table

## FAQ
- 403 Forbidden: ensure eCapture’s actual listening address matches the `WebSocket` field; `Origin` is auto-set; if a fixed value is needed, adjust the source
- Ensure `--ecaptureq` address in eCapture startup parameters ends with `/`
- Connected but no traffic? Check that Burp Proxy has "Support invisible proxying" enabled

## Changelog
2025.12.13
- Fixed issue where RAW for non-HTTP requests did not display; it now shows correctly
- Added index sequence; removed Src/Dst columns; added clear logs; added log persistence synchronized with the Burp project to facilitate historical investigation and analysis

## Compliance
This project is for security testing and research only. Please comply with local laws and the authorized scope of target systems.

## Acknowledgements
Special thanks to the author of eCapture for open sourcing and providing high-quality traffic HOOK and event output capabilities. eCapture’s stability and engineering quality laid the foundation for this project.

