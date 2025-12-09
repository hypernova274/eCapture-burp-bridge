# eCapture-burp-bridge

一个连接本地 eCapture 的 Burp Suite 插件： WebSocket 客户端接收 Protobuf 事件流，解析出原始 HTTP 报文并透明转发到 Burp Proxy，同时把所有事件（包含非 HTTP）获取，便于调试和分析移动端/应用的网络流量。

## 特性
- 连接本地 eCapture（`ws://`/`wss://`），自动设置 `Origin` 头，规避 CSWSH 403 拒绝
- 解析 Protobuf `LogEntry`，忽略心跳/运行日志，仅处理 `Event`
- HTTP 请求透明转发到 Burp Proxy（Invisible Proxy 模式友好）
- 所有事件入表显示：HTTP 与非 HTTP统一观测，非 HTTP 使用 `Method=NON-HTTP`、`HTTP=RAW` 并标注 `Type`
- 计数标签实时显示：`总数`、`HTTP`、`非HTTP`
- 搜索/过滤（方法、主机、状态码）与一键导出所选/全部
- 自动重连（指数退避），连接状态可视化

## 架构
- Source：eCapture 在 `ws://127.0.0.1:28257/` 输出 Protobuf 事件
- Bridge：WebSocket 客户端连接 → 解析 `Event` → 识别 HTTP → 转发到 Burp（仅 HTTP） → 所有事件入表
- Destination：Burp Proxy（例如 `127.0.0.1:28887`），开启 Invisible Proxy

## 环境要求
- Java 21
- Gradle 8.x
- Burp Suite（Montoya API 2025.11支持）

## 构建
```powershell
# 在项目根目录
.\gradlew.bat shadowJar
# 生成的插件 Jar：
# build\libs\eCapture-Bridge-0.1.0.jar
```

## 安装与使用
1. 打开 Burp → Extender → Extensions → Add → 选择 `build\libs\eCapture-Bridge-0.1.0.jar`
2. 连接手机，设置 ADB 端口转发： ```bash adb forward tcp:28257 tcp:28257```
3. 启动 eCapture (开启 WebSocket 服务)：
\# 替换 <PID> 为目标 App 的 PID 
```./ecapture tls -p <PID> --ecaptureq=ws://0.0.0.0:28257/``
4. 切换到 “eCapture Bridge” 标签页，填写：
   - `WebSocket`：eCapture 地址（例如 `ws://127.0.0.1:28257/`）
   - `Proxy Host`：Burp 代理主机（默认 `127.0.0.1`）
   - `Port`：Burp 代理端口（例如 `28887`）
5. 点击 `Connect`，状态显示 “connecting” → “connected” 即成功
6. 产生网络流量后，面板表格会显示事件；选中行：
   - HTTP：底部显示 Request/Response
   - 非 HTTP：底部显示 Raw（原始字节）
![image](https://github.com/user-attachments/assets/726e75bf-cdc8-4029-80e5-36965830a2cd)

<img width="2560" height="1200" alt="image-20251210015217178" src="https://github.com/user-attachments/assets/ce70f1ce-0f26-416a-b799-f03541fe7ac0" />


## 界面说明

<img width="2554" height="1199" alt="image-20251210012109599" src="https://github.com/user-attachments/assets/39d26ad6-8e69-4ce6-8ee9-a967d388971b" />


- 顶部：连接/断开、自动重连、重试次数、最大历史、搜索/过滤框
- 状态标签：未连接 / 连接中… / 已连接 / Closed / Error
- 计数标签：`总数 N`、`HTTP H`、`非HTTP NH`
- 表格列：`Time, Src, Dst, Method, Path, Host, HTTP, Type, Status, Length, Proc, UUID`
- 导出：支持导出所选事件或全部事件到文本文件

## 技术细节
- WebSocket：使用 Java-WebSocket，握手时根据 `ws://`/`wss://` 自动计算 `Origin: http://host:port` / `https://host:port`
- Protobuf：解析 `LogEntry`，仅处理 `LOG_TYPE_EVENT`；心跳与运行日志忽略
- HTTP 识别：前缀匹配 `GET/POST/PUT/DELETE/HEAD/OPTIONS/CONNECT`
- 非 HTTP 标记：`Method=NON-HTTP`、`HTTP=RAW`、`Path/Host` 置空，并从 `Event.type` 映射 `Type`（如 `TLS`、`HTTP2-Frame`、`MQTT`、`DNS`、`MySQL`、`Redis`、`PostgreSQL`、`MongoDB`、`WebSocket`、`QUIC`、`RAW`）
- 响应关联：按请求字节哈希与 Burp MessageId 关联，回填 `Status/Response` 并刷新表格

## 常见问题
- 403 Forbidden：确认 eCapture 实际监听与 `WebSocket` 字段一致；`Origin` 已自动设置，如需固定值可调整源码
- 请确保 eCapture 启动参数中的 `--ecaptureq` 地址末尾带有 `/`
- 连上后没有流量？ 请检查 Burp Proxy 设置中是否开启了 "Support invisible proxying"

## 合规声明
本项目仅用于安全测试与研究，请遵循当地法律法规与目标系统授权范围。

## 致谢
特别感谢 eCapture 作者的开源精神，为社区提供了高质量的流量HOOK与事件输出能力。eCapture 的稳定性与工程质量为本项目的实现奠定了基础。
