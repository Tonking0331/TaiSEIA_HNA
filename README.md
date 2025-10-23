# TaiSEIA_HNA
TaiSEIA HNA程式，未來將移植至ESP32
驗證程序總結這個單一測試序列將按順序驗證所有已整合的複雜流程，涵蓋了主動發送和被動回應的所有關鍵步驟：
階段步驟 (Client)功能碼 (F/SF)伺服器動作 (HNA)預期結果 (Client)
I. 連線/重建1. TCP 連線N/AHNA 主動發送 H'01/H'00成功連線，收到 H'01/H'00 (Client 回覆 ACK)
2. Client 接收 H'01/H'01H'01/H'01HNA 主動發送 H'01/H'01收到 H'01/H'01 (Client 回覆 F1/00)
3. Client 接收 H'05/H'04H'05/H'04HNA 主動發送 H'05/H'04收到 H'05/H'04 (Client 回覆 ACK，重建完成)
II. 註冊
4. Client 發送啟動註冊H'03/H'00HNA 被動回覆 ACK收到 H'F0/H'00
5. Client 發送讀取能力H'03/H'02HNA 被動回覆 F1/00 + Data收到 H'F1/H'00 (含支援能力)
III. SA 管理/轉傳
6. Client 發送啟動轉傳H'05/H'01HNA 回覆 ACK + 主動發送 H'05/H'05收到 H'F0/H'00，接著收到 H'05/H'05 (Client 回覆 ACK)
7. Client 接收報告H'05/H'04HNA 主動發送 H'05/H'04收到 H'05/H'04 (Client 回覆 ACK，轉傳完成)
IV. SA 監控
8. Client 發送設定狀態H'04/H'02HNA 被動回覆 ACK收到 H'F0/H'00
9. Client 發送讀取狀態H'04/H'01HNA 被動回覆 F1/00 + Data收到 H'F1/H'00 (含 SA 狀態數據)
V. 結束
10. 關閉連線N/AN/A連線關閉
