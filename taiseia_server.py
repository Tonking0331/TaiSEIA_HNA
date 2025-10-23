# taiseia_server.py
import asyncio
import struct
import json
import time
from taiseia_common import * # 引入共用模組

# ----------------------------------------------------
# 伺服器狀態管理
# ----------------------------------------------------
class ServerState:
    def __init__(self):
        # 0: 正常模式, 1: 處理網路重建, 2: 處理 SA 轉傳
        self.mode = 0 
        self.rebuild_step = 0 # 網路重建流程狀態
        self.relay_step = 0   # SA 管理/轉傳流程狀態

# ----------------------------------------------------
# 1. TCP 服務處理 (HNA 核心邏輯)
# ----------------------------------------------------

async def handle_taiseia_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global EVENT_ID_COUNTER
    server_state = ServerState()
    
    addr = writer.get_extra_info('peername')
    print(f"\n[TCP] Connection established from {addr}. Initializing State...")

    # --- 流程起始：網路重建判斷 ---
    # 這裡模擬 HNA 在每次新連線時啟動網路重建流程
    server_state.mode = 1
    server_state.rebuild_step = 1 # Step 1: 啟動 HNA 主動通知上線
    
    # --- HNA 主動通知已上線 (網路重建步驟 2) ---
    try:
        if server_state.rebuild_step == 1:
            print(f"[TCP] HNA 主動發送 H'01/H'00 通知已上線 (重建 Step 2)...")
            notify_online_packet = build_taiseia_packet(
                sender_id=RECEIVER_ID, receiver_id=SENDER_ID, group_id=0xFF,
                function_id=0x01, sub_function_id=0x00, data=b''
            )
            writer.write(notify_online_packet)
            await writer.drain()
            server_state.rebuild_step = 2 # 等待 HC 對通知的 ACK (Step 3)
            
    except Exception as e:
        print(f"[TCP] Error during initial notification: {e}")
        writer.close()
        await writer.wait_closed()
        return


    # --- 主接收迴圈 (處理 HC 回覆和指令) ---
    try:
        while True:
            data = await reader.read(4096) 
            if not data: break 

            header_info = parse_taiseia_response(data)
            if "error" in header_info:
                # CRC 或格式錯誤，回覆 F0/03 CRC 錯誤
                response_packet = create_ack_response(SENDER_ID, RECEIVER_ID, 0, 0, 0x03)
                writer.write(response_packet)
                await writer.drain()
                continue
            
            func_id = header_info['function_id']
            sub_func_id = header_info['sub_function_id']
            packet_data = header_info['data']
            
            response_packet = b'' # 預設不回覆

            # ----------------------------------------------------
            # A. 網路重建流程 (優先處理)
            # ----------------------------------------------------
            if server_state.mode == 1:
                # 重建 Step 3 (收到 H'01/H'00 的 ACK)
                if server_state.rebuild_step == 2 and func_id == 0xF0 and sub_func_id == 0x00:
                    print(f"[TCP] 收到 HC 對 H'01/H'00 的 ACK (重建 Step 3)。")
                    # HNA 主動發送 讀取 ID 給 HC (重建 Step 6)
                    request_id_packet = build_taiseia_packet(
                        sender_id=RECEIVER_ID, receiver_id=header_info['sender_id'], group_id=0xFF,
                        function_id=0x01, sub_function_id=0x01, data=b''
                    )
                    writer.write(request_id_packet); await writer.drain()
                    server_state.rebuild_step = 3 # 等待 HC 回覆 ID (Step 7)
                    continue

                # 重建 Step 7 (收到 HC 回覆 ID 的 F1/00)
                elif server_state.rebuild_step == 3 and func_id == 0xF1 and sub_func_id == 0x00:
                    print(f"[TCP] 收到 HC 對 H'01/H'01 的回覆 (重建 Step 7)。")
                    # HNA 主動發送 報告 (重建 Step 8)
                    report_packet = build_taiseia_packet(
                        sender_id=RECEIVER_ID, receiver_id=header_info['sender_id'], group_id=0xFF,
                        function_id=0x05, sub_function_id=0x04, data=b'\x00'
                    )
                    writer.write(report_packet); await writer.drain()
                    server_state.rebuild_step = 4 # 等待 HC 回覆報告的 ACK (Step 9)
                    continue

                # 重建 Step 9 (收到 HC 對報告的 ACK)
                elif server_state.rebuild_step == 4 and func_id == 0xF0 and sub_func_id == 0x00:
                    print(f"[TCP] 收到 HC 對 H'05/H'04 的 ACK (重建 Step 9)。網路重建完成。")
                    server_state.mode = 0 # 進入正常模式
                    server_state.rebuild_step = 0
                    pass # 使用預設的 ACK (對 ACK 的 ACK)

            # ----------------------------------------------------
            # B. SA 管理/轉傳流程 (需要狀態追蹤)
            # ----------------------------------------------------
            elif server_state.mode == 2:
                # 轉傳 Step 6 (收到 HC 對 H'05/H'05 通知封包的 ACK)
                if server_state.relay_step == 1 and func_id == 0xF0 and sub_func_id == 0x00:
                    print(f"[TCP] 收到 HC 對 H'05/H'05 通知封包的 ACK。準備發送報告 (Step 7)...")
                    # HNA 主動發送 報告封包 (Step 7)
                    report_packet = build_taiseia_packet(
                        sender_id=RECEIVER_ID, receiver_id=header_info['sender_id'], group_id=0xFF,
                        function_id=0x05, sub_function_id=0x04, data=SA_REPORT_DATA
                    )
                    writer.write(report_packet); await writer.drain()
                    server_state.relay_step = 2 # 等待 HC 對報告的 ACK (Step 8)
                    continue

                # 轉傳 Step 8 (收到 HC 對 H'05/H'04 報告封包的 ACK)
                elif server_state.relay_step == 2 and func_id == 0xF0 and sub_func_id == 0x00:
                    print(f"[TCP] 收到 HC 對 H'05/H'04 報告封包的 ACK。SA 管理流程完成。")
                    server_state.mode = 0 # 流程結束，回到正常模式
                    server_state.relay_step = 0
                    pass # 使用預設的 ACK (對 ACK 的 ACK)

            # ----------------------------------------------------
            # C. 正常模式 (被動回應)
            # ----------------------------------------------------
            elif server_state.mode == 0:
                print(f"[TCP] 收到指令 F=H'{func_id:02X}', SF=H'{sub_func_id:02X}'")

                if func_id == 0x00: # HNA 設定
                    if sub_func_id == 0x06: # 讀取 RTC 設定值
                        now = time.localtime()
                        rtc_data = struct.pack('!BBBBBBB', now[0]%100, now[1], now[2], now[3], now[4], now[5], now[6]) 
                        response_packet = build_taiseia_packet(
                            sender_id=RECEIVER_ID, receiver_id=header_info['sender_id'], group_id=0xFF,
                            function_id=0xF1, sub_function_id=0x00, data=rtc_data
                        )
                
                elif func_id == 0x01: # ID 管理 (讀取 ID)
                    if sub_func_id == 0x01: 
                        response_packet = build_taiseia_packet(
                            sender_id=RECEIVER_ID, receiver_id=header_info['sender_id'], group_id=0xFF,
                            function_id=0xF1, sub_function_id=0x00, data=ALL_ID_DATA
                        )

                elif func_id == 0x03: # HNA 註冊
                    if sub_func_id == 0x00: # 設定啟動註冊過程
                        response_packet = create_ack_response(header_info['sender_id'], RECEIVER_ID, func_id, sub_func_id, 0x00)
                    elif sub_func_id == 0x02: # 讀取 HNA 支援能力
                        response_packet = build_taiseia_packet(
                            sender_id=RECEIVER_ID, receiver_id=header_info['sender_id'], group_id=0xFF,
                            function_id=0xF1, sub_function_id=0x00, data=HNA_SUPPORT_CAPABILITY
                        )

                elif func_id == 0x04: # SA 裝置監控 (單次/批次)
                    if sub_func_id in [0x00, 0x02]: # 裝置監控請求/設定狀態
                        response_packet = create_ack_response(header_info['sender_id'], RECEIVER_ID, func_id, sub_func_id, 0x00)
                    elif sub_func_id == 0x01: # 讀取單次/批次狀態
                        response_packet = build_taiseia_packet(
                            sender_id=RECEIVER_ID, receiver_id=header_info['sender_id'], group_id=0xFF,
                            function_id=0xF1, sub_function_id=0x00, data=SIMULATED_SA_STATUS_DATA
                        )

                elif func_id == 0x05: # SA 裝置管理 (轉傳流程起始)
                    if sub_func_id == 0x01: # 設定 SA 裝置管理設定值 (HC 請求起始)
                        # HNA 回覆 F0/00 ACK (轉傳 Step 2)，並啟動狀態機
                        response_packet = create_ack_response(header_info['sender_id'], RECEIVER_ID, func_id, sub_func_id, 0x00)
                        writer.write(response_packet); await writer.drain() # 先發送 ACK
                        
                        # HNA 主動發送通知 (轉傳 Step 5)
                        notification_packet = build_taiseia_packet(
                            sender_id=RECEIVER_ID, receiver_id=header_info['sender_id'], group_id=0xFF,
                            function_id=0x05, sub_function_id=0x05, data=SA_NOTIFICATION_DATA
                        )
                        writer.write(notification_packet); await writer.drain()
                        
                        server_state.mode = 2 # 進入 SA 管理/轉傳模式
                        server_state.relay_step = 1 # 等待 HC 對通知的 ACK (Step 6)
                        continue # 避免發送預設 ACK
                    
                # 不支援的功能碼
                elif func_id not in [0xF0, 0xF1]: 
                    response_packet = create_ack_response(header_info['sender_id'], RECEIVER_ID, func_id, sub_func_id, 0x10) # F0/10

            # 5. 發送回應封包 (正常模式下，如果有回覆時)
            if response_packet and server_state.mode == 0:
                writer.write(response_packet)
                await writer.drain()

    except Exception as e:
        print(f"[TCP] An error occurred with {addr}: {e}")
    finally:
        print(f"[TCP] Closing connection with {addr}")
        writer.close()
        await writer.wait_closed()


# ----------------------------------------------------
# 2. UDP 服務處理 (服務發現)
# ----------------------------------------------------

class DiscoveryProtocol(asyncio.DatagramProtocol):
    # ... (此處代碼與 taiseia_common.py 中的 UDP 邏輯相同) ...
    def __init__(self, loop):
        self.loop = loop
        self.transport = None
        print(f"[UDP] Discovery listener started on port {UDP_DISCOVERY_PORT}")

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        server_ip = get_server_ip()
        if data.strip() == SEARCH_MAGIC_WORD:
            discovery_response = {
                "type": "discovery",
                "ip": server_ip,
                "port": TCP_SERVICE_PORT,
                "protocol": "TaiSEIA 101"
            }
            response_data = json.dumps(discovery_response).encode()
            self.transport.sendto(response_data, addr)
            print(f"[UDP] Responded with TCP info: {server_ip}:{TCP_SERVICE_PORT}")

    def error_received(self, exc):
        print(f"[UDP] Error received: {exc}")

    def connection_lost(self, exc):
        print("[UDP] Socket closed")

# ----------------------------------------------------
# 3. 主程式入口點
# ----------------------------------------------------

async def start_services():
    server_ip = get_server_ip()
    loop = asyncio.get_running_loop()

    tcp_server = await asyncio.start_server(
        handle_taiseia_client, host=server_ip, port=TCP_SERVICE_PORT, reuse_address=True
    )
    print(f"*** TCP TaiSEIA 101 Server is serving on {tcp_server.sockets[0].getsockname()} ***")

    await loop.create_datagram_endpoint(
        lambda: DiscoveryProtocol(loop), local_addr=('0.0.0.0', UDP_DISCOVERY_PORT)
    )

    try:
        await tcp_server.serve_forever()
    except asyncio.CancelledError:
        print("\nServices are being shut down...")
    finally:
        tcp_server.close()
        await tcp_server.wait_closed()

if __name__ == '__main__':
    print(f"Server ID (Receiver ID): {RECEIVER_ID.hex()}")
    print(f"Client ID (Sender ID) for testing: {SENDER_ID.hex()}")
    try:
        asyncio.run(start_services())
    except KeyboardInterrupt:
        print("Server process interrupted by user.")