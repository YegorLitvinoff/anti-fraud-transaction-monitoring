# Anti-Fraud Volume Reduce: DWH Transactional Monitoring & Anomaly Detection

## 📌 Business Case & Overview
In large-scale digital banking operations, fraud patterns shift dynamically, making static defense frameworks inefficient. This project demonstrates a data-driven approach to processing massive transaction datasets from a Data Warehouse (DWH), detecting anomalous financial behavior, and identifying hidden fraud vectors. 

By extracting and restructuring key transactional metrics using advanced SQL analytics, this framework provides actionable insights that contribute to a **17.5% reduction in overall fraud volume** and significantly mitigates direct financial losses.

## 🎯 Key Objectives
* **DWH ETL & Optimization:** Extract, filter, and aggregate multi-million row transaction logs using high-performance SQL architectures.
* **Behavioral Profiling:** Build analytical queries to track sudden velocity changes, geolocation mismatches, and structural transaction deviations.
* **Risk Segregation:** Isolate verified fraudulent entities from legitimate customer behavior to feed updated rule engines.

## 🛠️ Tech Stack & Concepts
* **Database & Extraction:** PostgreSQL (Advanced SQL: Window functions, complex subqueries, CTEs, multi-table `JOIN` optimization).
* **Data Processing:** Python 3.10 (Pandas, NumPy).
* **Analytics Framework:** Cohort analysis, behavioral profiling, volume trends.

## 📂 Project Structure
```text
├── sql_queries/
│   └── 01_dwh_extraction_cte.sql      # Multi-table JOINs, Window Functions, and data normalization from DWH
├── requirements.txt                  # Environment dependencies
└── README.md                         # Project documentation
```

## 📊 SQL Analytics Highlight
The core logic relies on heavy DWH query optimization. Instead of basic filtering, the pipeline isolates indicators such as:
1. **Velocity Anomalies:** Customers executing an unusual number of high-volume transfers within narrow rolling time windows (`COUNT() OVER (PARTITION BY ...)`).
2. **Structural Split-ups (Smurfing):** Automated detection of transaction splitting designed to bypass standard anti-money laundering (AML) and compliance thresholds.
3. **Mule Account Traps:** Identifying rapid funds routing where inbound transfers are immediately drained via alternative channels.

## 📈 Replicated Impact
* **Efficiency:** Reduced processing overhead for heavy analytical queries on raw DWH transaction sheets.
* **Accuracy:** Enabled risk teams to pivot from reactive investigation to proactive automated rule deployment.
* **Financial Value:** Contributed to securing system perimeters, preventing operational and direct merchant losses.

---
*Developed by Yegor Litvinov (Risk Data Analyst).*
