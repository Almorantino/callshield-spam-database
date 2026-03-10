# CallShield Spam Database

Data pipeline for building a phone spam detection dataset used by the CallShield iOS application.

This repository generates, scores, analyzes, and exports phone numbers that can be used in a CallKit Call Directory Extension.

---

# Architecture Overview

The system processes phone numbers through several stages:

number generation  
↓  
raw dataset  
↓  
scoring engine  
↓  
cluster analysis  
↓  
CallKit selection  

Resulting dataset is optimized for iOS call blocking and caller identification.

---

# Repository Structure

scripts/
- build_spam_database.py
- generate_numbers_from_prefix.py
- merge_generated_numbers.py
- analyze_number_clusters.py
- select_callkit_dataset.py

data/
- raw-source-database.json
- generated-numbers.json
- scored-database.json
- cluster-analysis.json
- device-database.json

output/
- spam-database.json

---

# Pipeline

## Generate Numbers

python3 scripts/generate_numbers_from_prefix.py

Creates:

data/generated-numbers.json

---

## Merge Generated Numbers

python3 scripts/merge_generated_numbers.py

Updates:

data/raw-source-database.json

---

## Build Scored Database

python3 scripts/build_spam_database.py

Creates:

data/scored-database.json

---

## Analyze Number Clusters

python3 scripts/analyze_number_clusters.py

Creates:

data/cluster-analysis.json

---

## Select Dataset for CallKit

python3 scripts/select_callkit_dataset.py

Creates:

data/device-database.json

---

# Scoring Logic

Spam score is computed using several signals:

- report volume
- scam flags
- spam category
- source reliability
- official telemarketing prefixes

Decision rules:

score >= 70 → block  
score 30–69 → identify  
score < 30 → ignore  

---

# Cluster Detection

Numbers are grouped by prefix.

Cluster analysis calculates:

- number of blocked numbers
- number of identified numbers
- ignore volume
- cluster risk score

Example clusters:

0948 → fraud cluster  
0162 → energy telemarketing  
0377 → BTP telemarketing  

---

# Device Dataset

The final dataset used by iOS contains:

blocked_numbers  
identified_numbers  

This dataset feeds the Call Directory Extension used by the CallShield application.

---

# Future Improvements

- cluster-based scoring bonuses
- campaign detection
- automated spam source ingestion
- large-scale prefix analysis
- dataset scaling to millions of numbers
