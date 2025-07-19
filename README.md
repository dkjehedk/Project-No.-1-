# Project-No.-1-
mkdir DarkKing-IntrusionGuard
cd DarkKing-IntrusionGuard
touch main.py detector.py gui.py db_handler.py requirements.txt README.md
import scapy.all as scapy
from joblib import load

model = load("model.pkl")  # النموذج المدرب سابقاً

def extract_features(pkt):
    if pkt.haslayer(scapy.IP):
        ip = pkt[scapy.IP]
        return [len(pkt), ip.ttl, ip.proto]
    return []

def classify_packet(features):
    return model.predict([features])[0]  # 0: عادي / 1: اختراق
    from detector import extract_features, classify_packet
import scapy.all as scapy

def monitor(interface):
    print(f"[+] مراقبة الواجهة: {interface}")
    scapy.sniff(iface=interface, store=False, prn=process)

def process(pkt):
    features = extract_features(pkt)
    if features:
        verdict = classify_packet(features)
        if verdict == 1:
            print("[!] تم كشف حزمة مشبوهة!")

if __name__ == "__main__":
    monitor("eth0")  # غيّر إلى wlan0 أو الواجهة المناسبة
    import tkinter as tk
from main import monitor

root = tk.Tk()
root.title("DarkKing Intrusion Guard")

def start():
    monitor("eth0")

tk.Label(root, text="👑 DarkKing Monitor").pack()
tk.Button(root, text="Start Monitoring", command=start).pack()
root.mainloop()
scapy
joblib
# 🛡️ DarkKing-IntrusionGuard

نظام اكتشاف التسللات الشبكية باستخدام Python وذكاء اصطناعي.

## الميزات
- تحليل حزم الشبكة
- كشف الهجمات باستخدام نموذج SVM
- واجهة رسومية بسيطة

## طريقة التشغيل
## المطور: دارك 👑
