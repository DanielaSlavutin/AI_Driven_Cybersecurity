# Autonomous SMB Anomaly Detection Pipeline

An end-to-end defensive monitoring system powered by Deep Learning and Explainable AI (xAI) designed to detect anomalies and lateral movement of ransomware within the SMB protocol, without relying on pre-configured signature matching
--- 
* **Student:** Daniela Slavutin
* **AI Driven Cybersecurity Course - Spring Semester 2026**
---
## Datasets & Acknowledgments

This project utilizes high-fidelity network captures from leading cybersecurity research institutions to ensure a robust and realistic evaluation:

1. **Normal Traffic Baseline:** The "Monday" (Normal Working Hours) subset of the **CIC-IDS2017** dataset, provided by the [Canadian Institute for Cybersecurity (CIC)](https://www.unb.ca/cic/datasets/ids-2017.html). 
2. **Malicious Ransomware Traffic:** Real-world ransomware captures from 2016-2017, including the infamous **WannaCry** outbreak. These were sourced from the **Stratosphere IPS Project** at the [Czech Technical University (CTU) in Prague](https://www.stratosphereips.org/), Faculty of Electrical Engineering. 

We thank these institutions for providing open-access datasets that enable the advancement of AI-driven cybersecurity research.

---

## Rationale & Objective

In many critical sectors today (such as healthcare, manufacturing plants and water/electricity utilities), legacy computing infrastructures and outdated communication protocols (e.g., SMBv1/v2) are still widely deployed. These environments are highly susceptible to modern ransomware outbreaks, where traditional signature-based security tools often fail against zero-day or evolved variants.

This project introduces a proactive solution: an unsupervised ML defense system that models and learns the organization's baseline of legitimate network behavior. By doing so, it detects minute statistical deviations during a ransomware's lateral movement or deployment phases, automatically translating complex neural network outputs into structured, actionable SOC analyst reports in RT.

---

## Feature Engineering

From raw network packet captures (PCAP/PCAPNG), the system filters for port 445 (SMB) and extracts dynamic time windows consisting of 50 consecutive packets for each individual data flow. On these sequences, 6 key features are computed:

1. **Shannon Entropy:** Measures the level of randomness within the payload. A high value (approaching 8.0) indicates heavily compressed or encrypted payloads, a defining characteristic of a ransomware's rapid encryption phase.
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

During comprehensive testing against live traffic baselines and historical captures of the WannaCry ransomware outbreak, the system demonstrated high statistical efficiecny:
* **Precision (Model Trust):** **98%** - Virtually eliminating alert fatigue for SOC analysts. When an anomaly is flagged, there is a 98% mathematical certainty that the activity is genuinely malicious.
* **False Alarm Rate:** **11.08%** - The minimal FPs observed are caused by legitimate yet statistically rare enterprise events, such as automated bulk network backups at the end of a business day.
* **Reconstruction Loss at Peak Attack:** While normal corporate SMB traffic consistently remains below the 3.52 boundary, WannaCry's and other ransomware exploitation and rapid encryption sequences yielded extreme error metrics ranging from **15.70 to 17.06**, ensuring clear, unambiguous alerts.

---

## xAI Integration & Production Interface

To bridge the gap between deep learning abstractions and everyday security operations, the pipeline integrates a robust **Explainable AI (xAI)** layer:

1. **The xAI Engine:** When a sequence violates the anomaly threshold, its precise statistical telemetry is automatically injected as context into a Large Language Model (**LLaMA 3.1** via the Groq API). The model interprets the multifaceted relationships between the 6 network features and outputs an immediate English triage report. This report explicitly clarifies *why* the neural network triggered and maps the indicators directly to corresponding ransomware lifecycle stages (e.g., scanning, exploit delivery, or file encryption).
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