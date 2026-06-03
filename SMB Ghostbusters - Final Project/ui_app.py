import streamlit as st
import os
import torch
import torch.nn as nn
import numpy as np
import joblib
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

# ENTROPY CALCULATION FUNCTION
def calculate_shannon_entropy(data):
  if not data or len(data) == 0: return 0
  data_arr = np.frombuffer(data, dtype=np.uint8)
  counts = np.bincount (data_arr, minlength=256)
  probs = counts / counts.sum()
  probs = probs[probs > 0]
  return -np.sum(probs * np.log2(probs))

# FEATURE EXTRACTION
def extract_sus_features(pcap_path, window_size=50):
    flows = {}
    print(f"Engineering Features for: {os.path.basename(pcap_path)} \n")

    try:
        with PcapReader(pcap_path) as pcap:
            for pkt in pcap:
                if pkt.haslayer(IP) and pkt.haslayer(TCP) and (pkt[TCP].dport == 445 or pkt[TCP].sport == 445):
                    src_ip = pkt[IP].src
                    timestamp = float(pkt.time)

                    if src_ip not in flows:
                        flows[src_ip] = []
                        inter_arrival_time = 0.0
                    else:
                        prev_time = flows[src_ip][-1][6]
                        inter_arrival_time = max(timestamp - prev_time, 0.0)
                    entr = calculate_shannon_entropy(pkt[TCP].load) if pkt[TCP].haslayer(Raw) else 0

                    size = pkt.len
                    is_outbound = 1.0 if pkt[TCP].dport == 445 else 0.0

                    opcode = 0
                    if pkt.haslayer(Raw):
                        payload = pkt[Raw].load
                        opcode = int(payload[12]) if len(payload) > 12 else 0
                    flows[src_ip].append([entr, inter_arrival_time, size, is_outbound, opcode, 0.0, timestamp])
    except Exception as e:
        print(f"Error reading {pcap_path}: {e}")
        return np.array([])

    sequences = []
    for ip in flows:
        f_data = flows[ip]
        if len(f_data) >= window_size:
            for i in range(len(f_data) - window_size + 1):
                window = f_data[i:i + window_size]
                iat_std = np.std([p[1] for p in window])
                final_window = [[p[0], p[1], p[2], p[3], p[4], iat_std] for p in window]
                sequences.append(final_window)
    return np.array(sequences)


class LSTMAutoencoder(nn.Module):
  def __init__(self, n_features, seq_len):
    super(LSTMAutoencoder, self).__init__()
    self.encoder = nn.LSTM(n_features, 32, batch_first=True, num_layers=2, dropout=0.1)
    self.bn = nn.BatchNorm1d(32)
    self.decoder = nn.LSTM(32, n_features, batch_first=True, num_layers=2, dropout=0.1)
    self.seq_len = seq_len

  def forward(self, x):
    _, (hidden, _) = self.encoder(x)
    h = hidden[-1]
    h_bn = self.bn(h)
    de_input = h_bn.unsqueeze(1).repeat(1, self.seq_len, 1)
    decoded, _ = self.decoder(de_input)
    return decoded

def gen_llama_xai(anomaly_sequence_raw_data, loss_value, threshold_value):
    api_key = os.getenv('API_KEY')
    client = Groq(api_key=api_key)

    avg_entropy = np.mean(anomaly_sequence_raw_data[:, 0])
    avg_iat = np.mean(anomaly_sequence_raw_data[:, 1])
    avg_packet_size = np.mean(anomaly_sequence_raw_data[:, 2])
    avg_direction = np.mean(anomaly_sequence_raw_data[:, 3])
    avg_opcode = np.mean(anomaly_sequence_raw_data[:, 4])
    avg_iat_std = np.mean(anomaly_sequence_raw_data[:, 5])

    prompt = f"""
  You are a Senior Cyber Security Analyst and an xAI (Explainable AI) assistant in a Security Operations Center (SOC).
  An LSTM Autoencoder anomaly detection model has triggered an alert on SMB traffic (port 445).

  Alert Details:
  - Model Type: LSTM Autoencoder (Unsupervised)
  - Sequence Reconstruction Loss: {loss_value:.4f} (Calculated Anomaly Threshold is {threshold_value:.4f})

  Extracted Network Features (average over 50 packets sequence):
  1. Shannon Entropy: {avg_entropy:.4f} (Scale: 0-8. Low means unencrypted/structured, high means encrypted/compressed)
  2. Inter-Arrival Time (IAT): {avg_iat:.6f} seconds (Time gap between sequential packets)
  3. Packet Size: {avg_packet_size:.1f} bytes
  4. Direction Ratio: {avg_direction:.4f} (1.0 means purely outbound requests to port 445, 0.0 means inbound responses)
  5. SMB Opcode: {avg_opcode:.1f} (Heuristic SMB2/3 command identifier from payload offset 12)
  6. IAT Standard Deviation (Jitter): {avg_iat_std:.6f} (Low variation indicates highly automated machine-driven behavior)

  Task:
  Provide a concise, professional explanation in English for the SOC tier 1 analyst.
  You MUST evaluate the numbers strictly and mathematically:
  - If Shannon Entropy is below 2.0, it is LOW (significantly unencrypted, structured traffic like SMBv1 legacy or null byte scans). Do NOT call it high.
  - If IAT Standard Deviation is high (e.g. > 10.0), it means high variance and bursty/scanning behavior with timeouts, not a tight continuous loop.
  - Notice that Direction Ratio is 1.0000 (100% outbound requests with NO responses), which indicates aggressive scanning/probing of dead or unresponsive hosts.

  Explain WHY the deep learning model flagged this sequence based on complex relationship between these 6 features.
  Correlate the findings to general malicious network intrusion phases and the lateral movement lifecycle-including unauthorized network reconnaissance, scanning, credential abuse (such as Pass-the-Hash), or automated propagation engines (such as WannaCry scanning, EternalBlue exploitation, or rapid encryption)-vs. normal enterprise SMB activity.
  """

    data = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        model="llama-3.1-8b-instant",
        temperature=0.2
      )

    return data.choices[0].message.content

@st.cache_resource
def load_pipeline():
    device = torch.device("cpu")
    scaler = joblib.load("data_scaler.bin")
    threshold = joblib.load("anomaly_threshold.bin")
    model = LSTMAutoencoder(n_features=6, seq_len=50).to(device)
    model.load_state_dict(torch.load("lstm_autoencoder_model.pth", map_location=device))
    model.eval()
    return model, scaler, threshold

st.set_page_config(page_title="SMB AI Detection Pipeline", layout="wide")
st.title("Ransomware Detection Pipeline")

try:
    model, scaler, threshold = load_pipeline()
except Exception as e:
    st.error(f"Failed to load model files. Please make sure the .bin and .pth files are in the directory. Error: {e}")
    st.stop()

uploaded_file = st.file_uploader("Upload Network Capture(PCAP/PCAPNG)", type=["pcap", "pcapng"])

if uploaded_file and st.button("Analyze Traffic"):
    with st.spinner("Processing packets and running interface..."):
        temp_path = "temp.pcap"
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        X_raw = extract_sus_features(temp_path, window_size=50)
        os.remove(temp_path)

        if X_raw.size > 0:
            M_samples, M_seq_len, M_features = X_raw.shape
            X_flat_scaled = scaler.transform(X_raw.reshape(-1, M_features))
            X_tensor = torch.FloatTensor(X_flat_scaled.reshape(M_samples, M_seq_len, M_features)).to(torch.device("cpu"))

            with torch.no_grad():
                reconstructed = model(X_tensor)
                losses = torch.mean((X_tensor - reconstructed) ** 2, dim=(1, 2)).numpy()

            anomaly_indices = np.where(losses > threshold)[0]

            if len(anomaly_indices) > 0:
                max_idx = anomaly_indices[np.argmax(losses[anomaly_indices])]
                st.error("CRITICAL ANOMALY DETECTED!")
                st.write(f"Max Loss: {losses[max_idx]:.4f} | Threshold: {threshold:.4f}")

                with st.spinner("Generating xAI Report..."):
                    report = gen_llama_xai(X_raw[max_idx], losses[max_idx], threshold)
                    st.markdown("### LLaMA Report")
                    st.info(report)
            else:
                st.success("Traffic is clean!")
        else:
            st.warning("No valid SMB traffic found in the uploaded file.")
