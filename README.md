# Email Header Forensics
**GACS-7104 Computer Security | University of Winnipeg | April 2026**  
**Author:** Md Sahadatunnobi Chowdhury | Student ID: 3196720

---

## What This Project Does

This tool analyses email headers to detect phishing and spoofing attacks.
It combines 15 security rules (from RFC standards) with a machine learning
model to produce a transparent, reproducible forensic verdict.

---

## Files in This Repository

| File | Description |
|------|-------------|
| `email_forensics.py` | Main forensic tool — run this on any email |
| `notebooks/dataset.ipynb` | Generates the 100,000 synthetic training emails |
| `notebooks/email_security_detector.ipynb` | Trains the ML models |
| `notebooks/phishing_pot_parser.ipynb` | Parses real phishing emails |
| `notebooks/real_data_evaluation.ipynb` | Final evaluation on real data |
| `models/random_forest.pkl` | Trained Random Forest model |
| `models/xgboost.pkl` | Trained XGBoost model |
| `models/label_encoder.pkl` | Label encoder |
| `models/feature_cols.json` | 38 feature names used by the model |
| `data/email_security_dataset.csv` | 100,000 synthetic email records |
| `data/balanced_test_set.csv` | 4,242 evaluation records |

---

## How to Install

```bash
pip install pandas numpy scikit-learn xgboost shap joblib faker tqdm matplotlib seaborn
```

---

## How to Run

```bash
# Analyse a single email
python email_forensics.py "phishing_pot/sasa.eml"

# Analyse an entire folder
python email_forensics.py "phishing_pot/"
```

Results are saved to `forensics_report.csv`.

---

## How to Reproduce the Experiment

Run the notebooks in this order:

1. `dataset.ipynb` — generate synthetic dataset
2. `email_security_detector.ipynb` — train models
3. `phishing_pot_parser.ipynb` — parse real phishing emails
4. `real_data_evaluation.ipynb` — run balanced evaluation

All random seeds are fixed at **42** for reproducibility.

---

## Results

| Test | Weighted F1 |
|------|-------------|
| Synthetic test set (20,000 emails) | 0.9987 |
| Balanced real-world evaluation (4,242 emails) | **0.9998** |

- 100% detection on 1,414 real phishing emails
- Zero false positives on legitimate email

---

## Example Output

**Legitimate email:**
```
VERDICT : LIKELY LEGITIMATE  |  SCORE: 0.0001  |  BOTH AGREE -- SAFE
SPF: pass   DKIM: pass   DMARC: pass   Hops: 2
```

**Phishing email:**
```
VERDICT : PHISHING / THREAT DETECTED  |  SCORE: 0.9648  |  BOTH AGREE -- THREAT
SPF: none   DKIM: fail   DMARC: fail   Hops: 5
Rules fired: R01 (+0.8)  R02 (+2.0)  R03 (+3.0)  R04 (+2.0)  R05 (+2.0)
```

---

## Citation

```
Md Sahadatunnobi Chowdhury, "Email Header Forensics Using Authentication
and Routing Analysis: A Hybrid Rule-Based and Machine Learning Framework,"
GACS-7104, University of Winnipeg, April 2026.
```
