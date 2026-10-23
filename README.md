 Network Intrusion Detection System (IDS)



 1. Project Overview



This project implements a Python-based network traffic analysis and intrusion detection prototype. It processes a PCAP file, extracts traffic features, applies rule-based detection, evaluates results against labels for a synthetic dataset, and displays findings through a Streamlit dashboard.



\*\*Important:\*\* The current implementation is a rule-based IDS prototype, not a trained AI model. Its traffic data is synthetic and intended for demonstration and testing.



 2. Objectives



\- Read network packets from a PCAP capture.

\- Extract source IP, packet count, bytes, duration, packet rate, destination-port diversity, protocol, and TCP SYN count.

\- Detect potential port scanning, high-volume flooding, and repeated TCP connection attempts.

\- Generate explainable alerts with severity, confidence labels, and reasons.

\- Present traffic and alert information in a web dashboard.

\- Evaluate the prototype on known synthetic scenarios.



 3. Technology Stack



\- Python

\- Scapy

\- Pandas

\- Streamlit

\- Matplotlib (installed; not currently required by the dashboard code)

\ Scikit-learn
- Isolation Forest (unsupervised anomaly detection)
- StandardScaler (feature scaling)



 4. Project Structure



```text

AI-Network-IDS/

├── data/

│   ├── sample\_traffic.pcap

│   └── traffic\_features.csv

├── reports/

│   └── alerts.csv
    └── ml_anomalies.csv

├── src/

│   ├── generate\_traffic.py

│   ├── extract\_features.py

│   ├── detector.py

│   ├── evaluate.py

│   └── dashboard.py
│   ├── ml_detector.py
│   └── demo_missed_case.py


├── screenshots/

├── requirements.txt

└── README.md

```



 5. Setup



Use Python 3.13 or a compatible Python version.



Create and activate a virtual environment:



```bat

python -m venv .venv

.venv\\Scripts\\activate

```



Install dependencies:



```bat

python -m pip install -r requirements.txt

```



 6. How to Run



Run these commands from the project root, with the virtual environment activated:



```bat

python src\\generate\_traffic.py

python src\\extract\_features.py

python src\\detector.py

python src\\evaluate.py

python -m streamlit run src\\dashboard.py

```



The dashboard normally opens at `http://localhost:8501`.



 7. Detection Rules



\*\*Possible port scan:\*\* Triggers when a source IP contacts at least 10 distinct TCP destination ports in the capture.



\*\*Possible DoS/flooding:\*\* Triggers when a source has at least 50 packets and a calculated rate of at least 500 packets per second.



\*\*Repeated TCP connection attempts:\*\* Triggers when a source has at least 12 TCP SYN packets across no more than 3 distinct destination ports, unless the high-volume flooding rule already applies.



These rules identify suspicious patterns, not confirmed attacks. Confidence labels are rule-based labels and have not been statistically calibrated.


### Machine-Learning Anomaly Detection

The prototype includes an Isolation Forest model trained on scaled source-IP traffic features, including packet count, bytes, duration, packet rate, destination-port diversity, and TCP SYN count. The model produces an anomaly label and anomaly score for each source record.

The current demonstration uses four synthetic source-IP records with a contamination setting of 0.25. The results illustrate how unsupervised anomaly detection can complement rule-based detection. They are not validated attack classifications, and an anomaly does not necessarily indicate malicious activity.


 8. Synthetic Dataset and Evaluation



The included capture is generated locally using Scapy. It contains four simulated source-IP scenarios: normal traffic, port scanning, high-volume traffic, and repeated SSH-directed TCP connection attempts.



The current source-level evaluation reports:



\- True positives: 3

\- False positives: 0

\- True negatives: 1

\- False negatives: 0

\- Precision: 100%

\- Recall: 100%

\- Accuracy: 100%



These metrics apply only to four designed synthetic examples. They must not be interpreted as representative real-world performance.



 9. Limitations



\- The dataset is synthetic rather than a collection of real-world captures.

\- The detector aggregates traffic by source IP rather than reconstructing complete network flows.

\- The packet-rate calculation uses the first and last observed packet timestamps for each source.

\- TCP SYN patterns cannot establish whether an authentication attempt failed.

\- Encrypted traffic limits visibility into application-level behavior.

\- Rule thresholds may produce false positives or miss attacks that do not match the configured patterns.

\- The current prototype does not contain a trained machine-learning model.

\- Performance and scalability have not been benchmarked on large captures.



 10. Future Improvements



\- Test on a suitable, publicly available labeled dataset.

\- Add more robust flow-based features and configurable thresholds.

\- Add authentication-log analysis for failed-login detection.

\- Compare rule-based detection with a trained machine-learning model.

\- Measure performance, false positives, and false negatives on a larger independent dataset.

\- Improve dashboard filtering, export, and reporting.


**Ambiguous or missed detection scenario:** An additional test simulated a source contacting nine distinct destination ports. The detector generated no alert because its port-scan threshold is ten ports. This demonstrates that scan-like activity below a fixed threshold may go undetected. The test illustrates a potential false negative, but it does not independently establish that a real attack occurred.



11. Ethical Use



Use the system only with traffic you own or are authorized to analyze. The included demonstration generates synthetic packets locally and does not transmit attack traffic to a real network.



