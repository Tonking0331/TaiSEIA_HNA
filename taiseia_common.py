# taiseia_common.py
import struct
import json
import socket
import asyncio

# --- 服務設定與 ID 資訊 ---
UDP_DISCOVERY_PORT = 50000
TCP_SERVICE_PORT = 50001
SEARCH_MAGIC_WORD = b'TAISEIA_SEARCH_REQUEST'

# 伺服器/接收端 ID: 6 bytes 範例
RECEIVER_ID = b'\x44\x44\x44\x44\x33\x33' 
# 客戶端/發送端 ID: 6 bytes 範例
SENDER_ID = b'\xAA\xAA\xAA\xAA\xBB\xBB'

# 模擬伺服器端持有的 ID 資訊
SIMULATED_USER_ID = b'\x11\x11\x11\x11' # 4 bytes
SIMULATED_HC_ID   = b'\xAA\xBB'        # 2 bytes
SIMULATED_HNA_ID  = b'\x33\x33'        # 2 bytes
SIMULATED_CS_ID   = b'\x55\x55\x55\x55\x66\x66' # 6 bytes
ALL_ID_DATA = SIMULATED_USER_ID + SIMULATED_HC_ID + SIMULATED_HNA_ID + SIMULATED_CS_ID # 14 bytes

# 模擬 HNA 支援能力
HNA_SUPPORT_CAPABILITY = b'\x01\x00\x01\x00'
# 模擬 SA 狀態數據
SIMULATED_SA_STATUS_DATA = b'\x01\x01\x02' 
# 模擬 SA 報告數據
SA_REPORT_DATA = b'\x1A\x1B\x1C\x1D' 
# 模擬 SA 通知數據
SA_NOTIFICATION_DATA = b'\x01\x01'


# --- 全域事件序號，確保每次發送的事件序號遞增 ---
EVENT_ID_COUNTER = 1 


# --- 輔助函數：CRC-16 計算 ---
def crc16_ccitt(data: bytes, initial_value: int = 0xFFFF) -> int:
    crc = initial_value
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            crc &= 0xFFFF
    return crc


# --- 輔助函數：TaiSEIA 101 封包建構 ---
def build_taiseia_packet(
        sender_id: bytes,
        receiver_id: bytes,
        group_id: int,
        function_id: int,
        sub_function_id: int,
        data: bytes = b''
) -> bytes:
    """建構 TaiSEIA 101 二進制封包"""
    global EVENT_ID_COUNTER
    
    HEADER_ID = 0x13
    FIXED_HEADER_LENGTH = 24 
    TOTAL_LENGTH = FIXED_HEADER_LENGTH + len(data) + 2 
    
    event_id = EVENT_ID_COUNTER 
    EVENT_ID_COUNTER += 1       
    
    header_part = struct.pack(
        '!BH6s6sBHBHH', 
        HEADER_ID, TOTAL_LENGTH, sender_id, receiver_id, group_id,
        event_id, function_id, sub_function_id,
        0, 0
    )
    
    payload_no_crc = header_part + data
    crc = crc16_ccitt(payload_no_crc)
    
    return payload_no_crc + struct.pack('!H', crc)

# --- 輔助函數：解析 TaiSEIA 101 封包 ---
def parse_taiseia_response(packet: bytes) -> dict:
    """解析 TaiSEIA 101 封包的固定標頭和 CRC"""
    if len(packet) < 26:
        return {"error": "Packet too short", "length": len(packet)}

    header_format = '!BH6s6sBHBHH' 
    header_size = struct.calcsize(header_format)

    # CRC 檢查
    payload_no_crc = packet[:-2]
    received_crc = struct.unpack('!H', packet[-2:])[0]
    calculated_crc = crc16_ccitt(payload_no_crc)
    
    if received_crc != calculated_crc:
        return {"error": "CRC Mismatch"}

    # 解析標頭
    header_tuple = struct.unpack(header_format, payload_no_crc[:header_size])
    
    return {
        "header_id": header_tuple[0],
        "packet_length": header_tuple[1],
        "sender_id": header_tuple[2], 
        "receiver_id": header_tuple[3], 
        "event_id": header_tuple[5],
        "function_id": header_tuple[6],
        "sub_function_id": header_tuple[7],
        "data": packet[header_size:-2]
    }
    
# --- 輔助函數：建構 ACK ---
def create_ack_response(sender_id: bytes, receiver_id: bytes, func_id: int, sub_func_id: int, ack_code: int) -> bytes:
    """創建 F0 認可 (ACK) 封包"""
    return build_taiseia_packet(
        sender_id=receiver_id,
        receiver_id=sender_id,
        group_id=0xFF,
        function_id=0xF0, # 認可 (ACK)
        sub_function_id=ack_code,
        data=b''
    )

# --- 輔助函數：獲取 IP ---
def get_server_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip