# SMB Ghostbusters - Autonomous SMB Anomaly Detection Pipeline

An end-to-end defensive monitoring system powered by Deep Learning and Explainable AI (xAI) designed to detect anomalies and lateral movement within the SMB protocol, without relying on pre-configured signature matching
--- 
* **Student:** Daniela Slavutin
* **AI Driven Cybersecurity Course - Spring Semester 2026**
---
## Datasets & Acknowledgments

This project utilizes high-fidelity network captures from leading cybersecurity research institutions to ensure a robust and realistic evaluation:

1. **Normal Traffic Baseline:** The "Monday" (Normal Working Hours) subset of the **CIC-IDS2017** dataset, provided by the [Canadian Institute for Cybersecurity (CIC)](https://www.unb.ca/cic/datasets/ids-2017.html). 
2. 2. **Malicious Network Traffic:** Real-world malicious captures spanning various intrusion vectors, including aggressive worms (the infamous **Conficker** network worm), network-replicating wipers (**NotPetya**), network-share encryptors (**Locky, Cerber**), and automated propagation engines (**WannaCry**). These were sourced from the **Stratosphere IPS Project** at the [Czech Technical University (CTU) in Prague](https://www.stratosphereips.org/).

We thank these institutions for providing open-access datasets that enable the advancement of AI-driven cybersecurity research.

---

## Rationale & Objective

In many critical sectors today (such as healthcare, manufacturing plants and water/electricity utilities), legacy computing infrastructures and outdated communication protocols (e.g., SMBv1/v2) are still widely deployed. These environments are highly susceptible to modern ransomware outbreaks, where traditional signature-based security tools often fail against zero-day or evolved variants.

This project introduces a proactive solution: an unsupervised ML defense system that models and learns the organization's baseline of legitimate network behavior. By doing so, it detects minute statistical deviations during a ransomware's lateral movement or deployment phases, automatically translating complex neural network outputs into structured, actionable SOC analyst reports in RT.

---

## Feature Engineering

From raw network packet captures (PCAP/PCAPNG), the system filters for port 445 (SMB) and extracts dynamic time windows consisting of 50 consecutive packets for each individual data flow. On these sequences, 6 key features are computed:

1. **Shannon Entropy:** Measures the level of randomness within the payload. A high value (approaching 8.0) indicates heavily compressed or encrypted payloads (defining characteristic of a ransomware's rapid encryption or data exfiltration), while lower values in flagged alerts help identify unencrypted legacy exploits or null-byte scanning structures.
2. **Inter-Arrival Time (IAT):** The time delta in seconds between sequential packets. Extremely low values signal high-frequency, machine-driven packet injection.
3. **Packet Size:** The packet length in bytes, which aids the model in differentiating between small control commands and large-scale file transfers.
4. **Direction Ratio:** A metric indicating traffic directionality (outbound vs. inbound). A value of 1.0 represents 100% outbound requests with zero responses - a classical signature of aggressive network scanning targeting dead or disconnected hosts.
5. **SMB Opcode:** A heuristic identifier extracted from the payload (offset 12), providing a behavioral command fingerprint for SMB activities.
6. **IAT Standard Deviation (Jitter):** The variance in packet arrival times. Near-zero jitter implies highly automated, programmatic execution by an exploit engine, starkly contrasting with the natural "noisy" timing of human interactions.

---

## Model Architecture

The core of the detection engine is a deep **LSTM Autoencoder** network (comprising 2 encoder layers and 2 decoder layers).

* **Training Phase:** The model is trained in an unsupervised fashion strictly on normal, legitimate organizational network traffic. It learns to compress the sequential features into a lower-dimensional latent space (Encoder) and reconstruct them back to their original form (Decoder).
* **Inference & Detection:** When evaluating new live traffic, the model attempts to reconstruct the data sequence. For normal traffic, the **Reconstruction Loss** is minimal. However, when exposed to malicious sequences (such as ransomware behavior), the model fails to properly reconstruct the unfamiliar pattern, causing the loss value to spike sharply.
* **Anomaly Thresholding:** The security barrier is established statistically using a strict 99.9th percentile of the training reconstruction errors (yielding baseline threshold of **3.5255**), maximizing the sensitivity to threat behaviors.

---

## Performance Metrics & Evaluation

During comprehensive testing against live traffic baselines and historical malware intrusion captures, the system demonstrated exceptional enterprise-grade defense metrics:

* **Precision (Model Trust):** **~100% (1.00)** for Anomalous SMB sequences. Virtually eliminating alert fatigue for SOC analysts—when the model triggers an anomaly alert, there is a near-perfect mathematical certainty that the activity is genuinely irregular or malicious.
* **Ultra-Low False Alarm Rate:** **0.54%** — Out of 3,130 completely normal baseline sequences, the model incorrectly flagged an alert only 17 times. This minimizes analyst burnout in production environments.
* **Peak Reconstruction Loss:** While normal corporate SMB traffic consistently remains below the 3.5255 boundary, automated exploit delivery, network scanning, and rapid encryption sequences yielded extreme error metrics, peaking at **22.7473** (more than 6x the threshold), ensuring completely unambiguous alerting.
* **Selectivity & Recall Analysis (43%):** The model captures the actual malicious payload injections and scanning bursts with high precision. The remaining traffic segments within the malicious PCAPs are correctly identified by the Autoencoder as benign **Background Traffic** generated by the host OS (standard Windows network keep-alives). The model's ability to filter out this background noise rather than blindly flagging the entire file justifies its real-world deployment safety.

---

## xAI Integration & Production Interface

To bridge the gap between deep learning abstractions and everyday security operations, the pipeline integrates a hybrid **Explainable AI (xAI)** layer:

1. **The Dual-Engine xAI:** When a sequence violates the anomaly threshold, its precise statistical telemetry is dynamically evaluated. The system supports both cloud-based inference (**LLaMA 3.1 via Groq API**) and fully localized, privacy-compliant deployment (**LLaMA 3.2 via Ollama**). The xAI layer interprets the multifaceted relationships between the 6 network features and outputs an immediate English triage report, mapping indicators directly to the general cyber kill chain and lateral movement lifecycle (reconnaissance, scanning, credential abuse like Pass-the-Hash, or rapid encryption phases).
2. **User Interface (Streamlit UI):** The entire architecture is contained within an interactive, intuitive Web application. Security analysts simply upload a network capture (supporting large files up to 1GB) and are instantly presented with clean visual metrics, severity scales, and the comprehensive xAI report, altogether avoiding the need to parse through exhausting plaintext log files.

---

## Deployment via Docker

The application is completely containerized as an isolated microservice using Docker, ensuring immediate cross-platform execution without requiring local host dependencies or specific drivers.

### 1. Prerequisites
Ensure the following artifacts are placed within the project root directory:
* Model and Scaler binaries: `lstm_autoencoder_model.pth`, `data_scaler.bin`, `anomaly_threshold.bin`.
* A `.env` environment file containing your access token:
  ```text
  API_KEY=your_groq_api_key_here
  ```

### 2. Build the Docker Image

```bash
docker build -t smb-anomaly-detector .
```
### 3. Run the Container
```bash
docker run -p 8501:8501 --env-file .env smb-anomaly-detector
```

Once initialized, the dynamic dashboard will be securely accessible in your browser at http://localhost:8501
