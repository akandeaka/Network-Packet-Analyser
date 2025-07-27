from flask import Flask, render_template, jsonify
from scapy.all import sniff
from threading import Thread
from utils.parser import extract_packet_info
import time

app = Flask(__name__)
captured_packets = []

def packet_collector():
    sniff(prn=lambda pkt: captured_packets.append(extract_packet_info(pkt)), store=0)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/packets")
def get_packets():
    return jsonify(captured_packets[-20:])

if __name__ == "__main__":
    t = Thread(target=packet_collector, daemon=True)
    t.start()
    app.run(debug=True)
