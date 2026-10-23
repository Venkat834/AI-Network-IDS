\# AI-Driven Network Traffic Analysis and Intrusion Detection System



\## 1. Abstract



Network intrusion detection is an important cybersecurity activity that helps identify potentially malicious communication by analyzing network traffic. This project implements a Python-based network traffic analysis and intrusion detection prototype using packet-capture processing, rule-based detection, unsupervised machine learning, and a web dashboard.



The system generates a synthetic packet capture using Scapy, extracts traffic features, applies detection rules, and uses an Isolation Forest model to identify unusual source-level traffic patterns. Results are displayed in a Streamlit dashboard, and an evaluation script compares source-level predictions with the known labels of four designed scenarios.



The prototype demonstrates an end-to-end workflow for network traffic analysis. However, its dataset is synthetic and small, and its results are not evidence of production-level intrusion detection performance. Further testing with larger, independently labeled network captures is required.



\## 2. Introduction



Modern computer networks face threats such as port scanning, denial-of-service activity, unauthorized connection attempts, and other suspicious communication patterns. Network intrusion detection systems help security analysts investigate these behaviors by examining network traffic and identifying activity that differs from expected patterns.



Traditional rule-based detection systems use predefined conditions to flag suspicious behavior. They are relatively straightforward to implement and explain, but their effectiveness depends on the quality of the rules and selected thresholds. Unsupervised machine-learning techniques provide another approach by identifying records that appear unusual relative to the data being analyzed.



The objective of this project is to build a practical prototype that combines these approaches. The system processes packet captures, extracts measurable features, produces explainable rule-based alerts, generates machine-learning anomaly scores, and presents results through a dashboard.



The prototype is intended for educational and demonstration purposes rather than deployment as a production security system.



\## 3. Objectives



The main objectives are:



\- Generate a safe, offline synthetic network traffic dataset.

\- Read packet data from a PCAP file.

\- Extract traffic features such as source IP, packet count, bytes, duration, packet rate, destination-port diversity, and TCP SYN count.

\- Detect potential port scanning, high-volume flooding, and repeated TCP connection attempts.

\- Implement an unsupervised anomaly detection component using Isolation Forest.

\- Display traffic summaries, rule-based alerts, and machine-learning results in a web dashboard.

\- Evaluate the rules against known labels for the synthetic demonstration.

\- Identify limitations and propose improvements for more realistic testing.



\## 4. Technologies Used



\*\*Python:\*\* Implements traffic generation, feature extraction, detection, and evaluation.



\*\*Scapy:\*\* Creates synthetic packets, writes PCAP files, and reads packet captures.



\*\*Pandas:\*\* Organizes extracted features and alert results into tabular data and CSV files.



\*\*Scikit-learn:\*\* Provides StandardScaler for feature scaling and Isolation Forest for unsupervised anomaly detection.



\*\*Streamlit:\*\* Provides the browser-based dashboard.



The project was developed and tested on Windows using Python 3.13.14 and a Python virtual environment.



\## 5. System Architecture and Methodology



The system follows a sequential processing pipeline.



First, a Python script generates synthetic packets locally and saves them to `data/sample\_traffic.pcap`. The generated scenarios include ordinary TCP traffic, a simulated port scan, high-volume TCP traffic, and repeated TCP SYN packets directed at an SSH service.



Second, the feature extraction script reads the capture using Scapy. Packets containing IPv4 information are grouped by source IP address. For each source, the program calculates packet count, total bytes, observation duration, packet rate, the number of unique TCP destination ports, observed protocols, and TCP SYN packet count. These features are saved to `data/traffic\_features.csv`.



Third, the rule-based detector analyzes the extracted source-level records. It checks destination-port diversity, packet count, packet rate, and SYN activity. Matching conditions produce alerts containing the source IP, alert category, severity, confidence label, and explanatory reason. Alerts are exported to `reports/alerts.csv`.



Fourth, an Isolation Forest model processes scaled numerical traffic features. The model produces an anomaly label and anomaly score for each source record. Its results are saved to `reports/ml\_anomalies.csv`.



Finally, the Streamlit dashboard displays traffic features, packet counts, rule-based alerts, and machine-learning anomaly results. A separate evaluation script compares the rule-based source-level predictions with the predefined synthetic labels.



\## 6. Detection Logic



\### 6.1 Possible Port Scan



The detector flags a source when it contacts at least ten distinct TCP destination ports in the capture. The simulated scan contacts fifteen ports and therefore triggers a high-severity alert.



The alert reason identifies the number of distinct destination ports contacted by the source. This provides an understandable explanation for the rule match.



\### 6.2 Possible DoS or Flooding



The detector flags a source when it has at least fifty observed packets and a calculated packet rate of at least 500 packets per second. The high-volume synthetic source contains 120 packets and has a measured rate of approximately 1,008.40 packets per second.



The system generates a high-severity alert for this source. However, a high packet rate alone does not establish that a denial-of-service attack occurred.



\### 6.3 Repeated TCP Connection Attempts



The detector flags a source with at least twelve TCP SYN packets across no more than three distinct destination ports, unless the high-volume flooding rule already applies to that source.



The simulated SSH-directed source triggers a medium-severity alert. TCP SYN packets indicate connection attempts, but they do not establish failed authentication. Consequently, this alert is not labeled as confirmed brute-force activity.



\### 6.4 Machine-Learning Anomaly Detection



The project includes an Isolation Forest model using packet count, bytes, duration, packet rate, unique destination-port count, and TCP SYN count. The numerical features are scaled before the model is fitted.



The model uses four synthetic source records and a contamination setting of 0.25. In the observed run, the high-volume source was classified as an anomaly, while the other three sources were classified as typical.



This demonstrates the implementation of an unsupervised learning technique. Because the dataset contains only four designed records, the model's output should be treated as exploratory rather than a validated security classification.



\## 7. Experimental Setup and Demonstration Scenarios



The synthetic PCAP contains 160 packets from four source IP addresses.



\*\*Scenario 1 — Normal traffic:\*\* The source `192.0.2.10` generates ten packets to one destination port at a low observed rate. No rule-based alert is generated.



\*\*Scenario 2 — Port scan:\*\* The source `198.51.100.20` contacts fifteen distinct destination ports. The detector produces a high-severity possible port-scan alert.



\*\*Scenario 3 — High-volume traffic:\*\* The source `198.51.100.30` generates 120 packets in a short interval. The measured rate exceeds the configured threshold, and a high-severity possible flooding alert is produced.



\*\*Scenario 4 — Repeated SSH-directed connections:\*\* The source `198.51.100.40` sends fifteen TCP SYN packets toward port 22. The detector generates a medium-severity repeated-connection alert. The packets do not prove that authentication attempts occurred or failed.



\*\*Scenario 5 — Potentially missed activity:\*\* An additional test supplies a source-level record with nine unique destination ports. Because the port-scan threshold is ten, no port-scan alert is generated. This illustrates how activity below a fixed threshold may go undetected. It is a threshold demonstration, not an independently confirmed attack.



\## 8. Evaluation and Results



The evaluation script uses four predefined source-level labels: one normal source and three simulated suspicious sources. A source is counted as detected when it appears in the rule-based alert output.



The observed results are:



\- True positives: 3

\- False positives: 0

\- True negatives: 1

\- False negatives: 0

\- Precision: 100%

\- Recall: 100%

\- Accuracy: 100%



Precision measures the proportion of predicted suspicious sources that are labeled suspicious. Recall measures the proportion of labeled suspicious sources that the rules identify. Accuracy measures the proportion of source records classified correctly.



These scores apply only to the four designed synthetic source records. The examples were constructed to exercise the detector's rules, and the evaluation is therefore not an independent test of generalization. The results cannot establish real-world accuracy, precision, or recall.



The fifth threshold test also illustrates a potential missed-detection case, but it is separate from the four-record evaluation. It should not be silently added to the reported confusion matrix because the original evaluation script does not include its ground-truth label.



The machine-learning output is evaluated separately and is not included in these rule-based metrics.



\## 9. Limitations and Challenges



The first limitation is the dataset. The included capture is synthetic, not a collection of real network traffic. Synthetic examples are useful for repeatable testing but do not reproduce the diversity of real applications, network congestion, user behavior, and attacker techniques.



Second, the system aggregates packets by source IP rather than reconstructing complete bidirectional network flows. This can combine unrelated activity from the same source and obscure the relationship between individual connections.



Third, packet rate is calculated using the earliest and latest packet timestamps observed for a source. This gives a simple average over the observation interval; it does not measure short-window bursts or sustained rates independently.



Fourth, rule thresholds introduce trade-offs. A threshold that is too low can produce false positives, while a threshold that is too high can miss slower or distributed activity. The nine-port test demonstrates this issue.



Fifth, repeated SYN packets cannot prove brute-force authentication. Detecting failed logins reliably would require appropriate authentication logs or application-level evidence. Encryption also limits the information available from packet contents.



Finally, the machine-learning model uses only four records. Its anomaly scores and labels are sensitive to the small sample and configuration. The project has not been benchmarked for throughput, memory usage, large captures, or performance under real network conditions.



\## 10. Future Improvements



Future work should evaluate the detector on a larger, independently labeled public dataset and document how the labels were obtained. Performance should be reported on separate training and test data, with a clear definition of what counts as a positive event.



The feature extraction process could be improved by constructing bidirectional flows, measuring time-window statistics, handling additional IP protocols, and accounting for incomplete captures. Detection thresholds could be made configurable and evaluated against false-positive and false-negative trade-offs.



Authentication-log analysis could provide stronger evidence for failed-login detection. The machine-learning component should be trained and evaluated on more representative data, with model parameters selected using a documented validation procedure.



The dashboard could also be extended with PCAP upload, downloadable reports, time-window filtering, and more detailed alert investigation. Before operational use, the system would require performance testing, security review, and validation in an authorized environment.



\## 11. Ethical and Safe Use



The included traffic generator creates synthetic packets locally and writes them to a capture file. It does not send attack traffic to a real network. Real packet captures should only be collected and analyzed with appropriate authorization, and sensitive information in captured traffic should be handled carefully.



The system's alerts are indicators for further investigation, not proof of malicious intent. Analysts should validate alerts using additional evidence before making incident decisions.



\## 12. Conclusion



This project implements an end-to-end network traffic analysis prototype using Scapy, Pandas, Scikit-learn, and Streamlit. It generates a synthetic PCAP, extracts source-level traffic features, applies explainable detection rules, produces Isolation Forest anomaly results, and presents findings in a dashboard.



The prototype successfully demonstrates port-scan detection, high-volume traffic detection, repeated connection-attempt detection, and a threshold-based missed-case example. It also demonstrates how rule-based methods and unsupervised anomaly detection can be presented together.



The current results are limited by the small synthetic dataset and simple feature aggregation. The reported 100% rule-based evaluation scores apply only to the four predefined examples and must not be generalized to real networks. Testing on larger, independently labeled captures is the essential next step toward a more reliable intrusion detection system.

