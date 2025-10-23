# taiseia_client.py
import asyncio
import socket
import json
import struct
import time
from taiseia_common import * # 引入共用模組

# 輔助函數：發送 ACK
def build_ack_packet(sender_id: bytes, receiver_id: bytes, ack_code: int) -> bytes:
    """建構 F0 認可 (ACK) 封包"""
    return build_taiseia_packet(
        sender_id=sender_id,
        receiver_id=receiver_id,
        group_id=0xFF,
        function_id=0xF0, # 認可 (ACK)
        sub_function_id=ack_code,
        data=b''
    )

def parse_id_data(data: bytes) -> dict:
    """解析 H'01 / H'01 回應中的 14 bytes ID 數據"""
    if len(data) < 14:
        return {"error": "ID Data too short"}
        
    return {
        "User ID": data[0:4].hex(),
        "HC ID": data[4:6].hex(),
        "HNA ID": data[6:8].hex(),
        "CS ID": data[8:14].hex()
    }


async def discovery_server(search_ip='127.0.0.1') -> tuple[str, int]:
    """步驟 1: 發送 UDP 搜尋並獲取 TCP 服務資訊"""
    # ... (此處使用 taiseia_common.py 中的 UDP 邏輯，與 client 腳本中相同) ...
    print(f"\n--- 步驟 1: 服務發現 (UDP) ---")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) 
    sock.settimeout(2.0)
    
    try:
        sock.sendto(SEARCH_MAGIC_WORD, (search_ip, UDP_DISCOVERY_PORT)) 
        data, addr = sock.recvfrom(1024)
        response = json.loads(data.decode())
        if response.get('type') == 'discovery':
            ip, port = response['ip'], response['port']
            print(f"✅ 成功發現伺服器: TCP @ {ip}:{port}")
            return ip, port
        print("UDP 回覆格式錯誤。")
    except socket.timeout:
        print("❌ 錯誤：未收到伺服器回覆 (Timeout)。")
    except Exception as e:
        print(f"❌ UDP 錯誤: {e}")
    finally:
        sock.close()
    return None, None


async def run_taiseia_test(server_ip: str, server_port: int):
    # --- 步驟 2: 建立 TCP 連線 (Client 進入網路重建模式) ---
    print(f"\n--- 步驟 2: 建立 TCP 連線 (Client 進入重建等待模式) ---")
    try:
        reader, writer = await asyncio.open_connection(server_ip, server_port)
        print(f"✅ 成功連線到 {server_ip}:{server_port}。")
    except ConnectionRefusedError:
        print(f"❌ 錯誤：拒絕連線，請確認伺服器正在運行。")
        return

    # --- 流程狀態機 ---
    test_step = 1 # 1-網路重建, 2-註冊, 3-管理, 4-監控, 5-結束
    rebuild_step = 1 # 網路重建流程狀態
    relay_step = 0 # 轉傳流程狀態

    try:
        while True:
            # 讀取數據 (等待 HNA 主動發送或回覆)
            response_data = await reader.read(4096)
            if not response_data:
                break
            
            response = parse_taiseia_response(response_data)
            if "error" in response:
                print(f"❌ 解析錯誤: {response['error']}")
                break

            func_id = response['function_id']
            sub_func_id = response['sub_function_id']
            
            print(f"[HC] 收到封包 F=H'{func_id:02X}', SF=H'{sub_func_id:02X}'. 狀態: {test_step}-{rebuild_step}-{relay_step}")

            # ----------------------------------------------------
            # 狀態 1: 網路重建 (HC 被動處理)
            # ----------------------------------------------------
            if test_step == 1:
                if rebuild_step == 1 and func_id == 0x01 and sub_func_id == 0x00: # 收到 H'01/H'00 (通知已上線)
                    ack_packet = build_ack_packet(SENDER_ID, RECEIVER_ID, 0x00)
                    writer.write(ack_packet); await writer.drain()
                    rebuild_step = 2 # 等待 H'01/H'01 (讀取 ID)
                elif rebuild_step == 2 and func_id == 0x01 and sub_func_id == 0x01: # 收到 H'01/H'01 (讀取 ID)
                    id_data = b'\x11\x11\x11\x11\xAA\xBB\x33\x33\x55\x55\x55\x55\x66\x66' 
                    reply_packet = build_taiseia_packet(SENDER_ID, RECEIVER_ID, 0xFF, 0xF1, 0x00, id_data)
                    writer.write(reply_packet); await writer.drain()
                    rebuild_step = 3 # 等待 H'05/H'04 (報告)
                elif rebuild_step == 3 and func_id == 0x05 and sub_func_id == 0x04: # 收到 H'05/H'04 (報告)
                    ack_packet = build_ack_packet(SENDER_ID, RECEIVER_ID, 0x00)
                    writer.write(ack_packet); await writer.drain()
                    print("✅ 網路重建流程完成。")
                    test_step = 2 # 進入下一步驟：註冊
                    rebuild_step = 0
                    break # 跳出等待迴圈，開始主動測試

            # ----------------------------------------------------
            # 狀態 3: SA 管理/轉傳 (HC 主動後，被動處理通知和報告)
            # ----------------------------------------------------
            elif test_step == 3:
                # 轉傳 Step 6 (收到 H'05/H'05 通知封包)
                if relay_step == 1 and func_id == 0x05 and sub_func_id == 0x05:
                    ack_packet = build_ack_packet(SENDER_ID, RECEIVER_ID, 0x00)
                    writer.write(ack_packet); await writer.drain()
                    relay_step = 2 # 等待 H'05/H'04 (報告)

                # 轉傳 Step 8 (收到 H'05/H'04 報告封包)
                elif relay_step == 2 and func_id == 0x05 and sub_func_id == 0x04:
                    ack_packet = build_ack_packet(SENDER_ID, RECEIVER_ID, 0x00)
                    writer.write(ack_packet); await writer.drain()
                    print("✅ SA 管理/轉傳流程完成。")
                    test_step = 4 # 流程結束，進入下一步驟
                    break # 跳出等待迴圈，開始主動測試
            
            # 忽略所有非流程中的 ACK/回應
            elif func_id in [0xF0, 0xF1]:
                pass
            
            else:
                print(f"[HC] 收到未處理封包 F=H'{func_id:02X}', SF=H'{sub_func_id:02X}'.")

    except Exception as e:
        print(f"Client Error during TCP loop: {e}")
    
    # ----------------------------------------------------
    # 流程控制：主動發送指令 (只有在狀態機流程完成後才會執行)
    # ----------------------------------------------------
    
    if test_step == 2: # 步驟 2：執行註冊流程
        print(f"\n--- 步驟 2: HNA 註冊 (H'03) ---")
        # H'03/H'00 (啟動註冊)
        request_reg_start = build_taiseia_packet(SENDER_ID, RECEIVER_ID, 0xFF, 0x03, 0x00, b'')
        writer.write(request_reg_start); await writer.drain()
        await reader.read(4096) # 讀取 HNA 的 ACK
        
        # H'03/H'02 (讀取 HNA 支援能力)
        request_read_cap = build_taiseia_packet(SENDER_ID, RECEIVER_ID, 0xFF, 0x03, 0x02, b'')
        writer.write(request_read_cap); await writer.drain()
        response_data = await reader.read(4096)
        response = parse_taiseia_response(response_data)
        print(f"✅ 註冊：讀取能力回覆 F=H'{response.get('function_id',0):02X}'/SF=H'{response.get('sub_function_id',0):02X}'")
        test_step = 3 # 進入下一步驟：SA 管理/轉傳

    if test_step == 3: # 步驟 3：SA 管理/轉傳流程 (啟動)
        print(f"\n--- 步驟 3: SA 管理/轉傳 (H'05/H'01 啟動) ---")
        request_management = build_taiseia_packet(SENDER_ID, RECEIVER_ID, 0xFF, 0x05, 0x01, b'\x01\x00\x01')
        writer.write(request_management); await writer.drain()
        relay_step = 1 # 等待通知/報告
        # 重新進入 while 迴圈處理 HNA 主動發送的封包
        
    if test_step == 4: # 步驟 4：執行單次/批次監控
        print(f"\n--- 步驟 4: SA 裝置監控 (H'04) ---")
        # H'04/H'02 (設定狀態)
        request_monitor_set = build_taiseia_packet(SENDER_ID, RECEIVER_ID, 0xFF, 0x04, 0x02, b'\x01\x01')
        writer.write(request_monitor_set); await writer.drain()
        await reader.read(4096) # 讀取 HNA 的 ACK
        
        # H'04/H'01 (讀取狀態)
        request_read_status = build_taiseia_packet(SENDER_ID, RECEIVER_ID, 0xFF, 0x04, 0x01, b'')
        writer.write(request_read_status); await writer.drain()
        response = parse_taiseia_response(await reader.read(4096))
        print(f"✅ 監控：讀取狀態回覆 F=H'{response.get('function_id',0):02X}'/SF=H'{response.get('sub_function_id',0):02X}'")
        test_step = 5 # 進入下一步驟：結束

    if test_step == 5:
        print(f"\n--- 步驟 5: 關閉 TCP 連線 ---")
        writer.close()
        await writer.wait_closed()
        print("✅ TCP 連線已關閉，所有流程測試完成。")
    
    if test_step < 5:
        # 如果流程未結束，且當前不在等待被動回覆，則再次運行迴圈，觸發下一個主動步驟
        await run_taiseia_test(server_ip, server_port)


async def main():
    # 這裡使用 '127.0.0.1' 進行本地測試
    ip, port = await discovery_server('127.0.0.1')
    
    if ip and port:
        # 重設全局事件計數器以確保測試流程從正確的事件 ID 開始
        global EVENT_ID_COUNTER
        EVENT_ID_COUNTER = 1 
        
        # 啟動測試流程
        await run_taiseia_test(ip, port)
    else:
        print("\n無法進行 TCP 測試，因為服務發現失敗。")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nClient process interrupted by user.")