#!/usr/bin/env python3


import os, sys, re, json, glob, argparse, datetime, warnings
import email as emaillib
from email import policy as email_policy
from pathlib import Path

# -- optional ML imports -- graceful fallback if not installed --
ML_AVAILABLE = False
try:
    import numpy  as np
    import pandas as pd
    import joblib
    import shap
    ML_AVAILABLE = True
except ImportError:
    pass

warnings.filterwarnings("ignore")


# ==============================================================
#  CONFIGURATION
# ==============================================================

CONFIG = {
    'BLOCK_THRESHOLD'      : 0.80,
    'QUARANTINE_THRESHOLD' : 0.50,
    'RULE_NORMALISER'      : 10.0,
    'RULE_THRESHOLD'       : 4.0,
    'RULE_WEIGHT'          : 0.35,
    'ML_WEIGHT'            : 0.65,
    'RISKY_TLDS': {'xyz','tk','ml','gq','cf','pw','cc',
                   'ru','info','biz','win','top','click'},
}


# ==============================================================
#  LAYER 1  -  RULE ENGINE
# ==============================================================

RULES = {
    'R01_SPF_FAIL'      : (+2.0, 'RFC 7208 + Shen et al. 2021'),
    'R01_SPF_SOFTFAIL'  : (+1.0, 'RFC 7208 Sec 8.5'),
    'R01_SPF_NONE'      : (+0.8, 'RFC 7208 + Banday 2011'),
    'R02_DKIM_FAIL'     : (+2.0, 'RFC 6376 + Shen et al. 2021 Attack A10'),
    'R02_DKIM_NONE'     : (+0.8, 'RFC 6376 + Banday 2011'),
    'R03_DMARC_FAIL'    : (+3.0, 'RFC 7489 -- compound SPF+DKIM failure'),
    'R03_DMARC_QUAR'    : (+2.0, 'RFC 7489 -- quarantine policy'),
    'R04_FROM_MISMATCH' : (+2.0, 'RFC 5321 + Shen et al. 2021 Attack A2'),
    'R05_DKIM_MISMATCH' : (+2.0, 'RFC 6376 Sec 8.15 + Shen et al. A10'),
    'R06_HIGH_HOPS'     : (+1.5, 'RFC 5321 + Banday 2011'),
    'R07_RISKY_TLD'     : (+1.5, 'Al-Hamar et al. 2021'),
    'R08_REPLY_HIJACK'  : (+1.5, 'RFC 5322 + Banday 2011'),
    'R09_LOOKALIKE'     : (+3.0, 'Shen et al. 2021 Attack A12'),
    'R10_DIGIT_DOMAIN'  : (+1.0, 'Shen et al. 2021'),
    'R00_ALL_AUTH_PASS' : (-2.0, 'Shen et al. 2021'),
}


def _extract_domain(addr):
    if not addr:
        return ''
    m = re.search(r'@([\w.\-]+)', addr)
    return m.group(1).lower().strip() if m else ''


def _is_lookalike(domain):
    if not domain:
        return False
    name = domain.split('.')[0].lower()
    subs = {'0':'o','1':'l','3':'e','4':'a','5':'s','6':'g'}
    norm = name
    for d, l in subs.items():
        norm = norm.replace(d, l)
    brands = ['paypal','amazon','google','microsoft','apple','netflix',
              'facebook','instagram','linkedin','dropbox','outlook',
              'gmail','yahoo','bankofamerica','citibank','chase']
    if norm != name:
        for b in brands:
            if b in norm:
                return True
    for b in brands:
        if b in name and '-' in name:
            return True
    return False


def run_rule_engine(p):
    raw   = 0.0
    fired = []

    spf   = p.get('spf_result',  '').lower()
    dkim  = p.get('dkim_result', '').lower()
    dmarc = p.get('dmarc_result','').lower()
    hops  = int(p.get('hop_count', 1) or 1)
    hdr   = p.get('header_from_domain',   '').lower()
    env   = p.get('envelope_from_domain', '').lower()
    dkd   = p.get('dkim_signing_domain',  '').lower()
    rto   = _extract_domain(p.get('reply_to', ''))

    def add(rule_id):
        pts, src = RULES[rule_id]
        nonlocal raw
        raw += pts
        fired.append((rule_id, pts, src))

    if   spf == 'fail':      add('R01_SPF_FAIL')
    elif spf == 'softfail':  add('R01_SPF_SOFTFAIL')
    elif spf in ('none',''):  add('R01_SPF_NONE')

    if   dkim == 'fail':      add('R02_DKIM_FAIL')
    elif dkim in ('none',''):  add('R02_DKIM_NONE')

    if   dmarc in ('fail','reject'):  add('R03_DMARC_FAIL')
    elif dmarc == 'quarantine':        add('R03_DMARC_QUAR')

    if hdr and env and hdr != env:            add('R04_FROM_MISMATCH')
    if dkd and hdr and dkd != hdr:            add('R05_DKIM_MISMATCH')
    if hops >= 6:                             add('R06_HIGH_HOPS')

    tld = hdr.split('.')[-1].lower() if hdr else ''
    if tld in CONFIG['RISKY_TLDS']:           add('R07_RISKY_TLD')

    if rto and hdr and rto != hdr:            add('R08_REPLY_HIJACK')

    if _is_lookalike(hdr) or _is_lookalike(env):  add('R09_LOOKALIKE')

    name = hdr.split('.')[0] if hdr else ''
    if any(c.isdigit() for c in name):        add('R10_DIGIT_DOMAIN')

    if (spf == 'pass' and dkim == 'pass' and dmarc == 'pass'
            and hdr and env and hdr == env):  add('R00_ALL_AUTH_PASS')

    norm_score = max(0.0, min(1.0, raw / CONFIG['RULE_NORMALISER']))

    return {
        'raw_score'   : raw,
        'norm_score'  : round(norm_score, 4),
        'rule_flagged': raw >= CONFIG['RULE_THRESHOLD'],
        'fired'       : fired,
    }


# ==============================================================
#  LAYER 2 + 3  -  ML ENSEMBLE  +  SHAP
# ==============================================================

def _load_models(model_dir):
    md = Path(model_dir)
    rf        = joblib.load(md / 'random_forest.pkl')
    xgb       = joblib.load(md / 'xgboost.pkl')
    le        = joblib.load(md / 'label_encoder.pkl')
    with open(md / 'feature_cols.json') as f:
        feat_cols = json.load(f)
    explainer = shap.TreeExplainer(xgb)
    return rf, xgb, le, feat_cols, explainer


def _engineer_features(p, feat_cols):
    spf   = str(p.get('spf_result',  'none')).lower()
    dkim  = str(p.get('dkim_result', 'none')).lower()
    dmarc = str(p.get('dmarc_result','none')).lower()
    dmarc_policy     = str(p.get('dmarc_policy',         'none')).lower()
    dmarc_align_spf  = str(p.get('dmarc_alignment_spf',  'none')).lower()
    dmarc_align_dkim = str(p.get('dmarc_alignment_dkim', 'none')).lower()
    arc_seal   = str(p.get('arc_seal', ''))
    hdr        = str(p.get('header_from_domain',   '')).lower()
    env        = str(p.get('envelope_from_domain', '')).lower()
    hop_count  = int(p.get('hop_count', 1) or 1)
    spam_score = float(p.get('x_spam_score', 0) or 0)
    reply_to   = str(p.get('reply_to', ''))

    domain_aligned = int(hdr == env and bool(hdr))
    is_spoofed     = int(not domain_aligned)

    spf_map  = {'pass':4,'neutral':3,'softfail':2,'none':1,'fail':0,'permerror':0}
    dkim_map = {'pass':3,'none':1,'fail':0,'temperror':0}
    dmarc_res_map = {'pass':3,'none':2,'quarantine':1,'fail':0,'reject':0}
    dmarc_pol_map = {'reject':3,'quarantine':2,'none':1}

    spf_score    = spf_map.get(spf, 0)
    spf_pass     = int(spf == 'pass')
    spf_fail     = int(spf in ('fail','permerror'))
    spf_softfail = int(spf == 'softfail')
    spf_none     = int(spf == 'none')

    dkim_score = dkim_map.get(dkim, 0)
    dkim_pass  = int(dkim == 'pass')
    dkim_fail  = int(dkim in ('fail','temperror'))
    dkim_none  = int(dkim == 'none')

    dmarc_result_score = dmarc_res_map.get(dmarc, 0)
    dmarc_policy_score = dmarc_pol_map.get(dmarc_policy, 0)
    dmarc_pass         = int(dmarc == 'pass')
    dmarc_fail_f       = int(dmarc in ('fail','reject'))
    dmarc_align_spf_f  = int(dmarc_align_spf  == 'pass')
    dmarc_align_dkim_f = int(dmarc_align_dkim == 'pass')
    dmarc_both_aligned = int(dmarc_align_spf_f and dmarc_align_dkim_f)
    dmarc_none_align   = int(not dmarc_align_spf_f and not dmarc_align_dkim_f)

    all_auth_pass    = int(spf_pass and dkim_pass and dmarc_pass)
    auth_failures    = spf_fail + dkim_fail + dmarc_fail_f
    auth_total_score = spf_score + dkim_score + dmarc_result_score

    risky_tlds = CONFIG['RISKY_TLDS']
    hdr_tld = hdr.split('.')[-1].lower() if hdr else ''
    env_tld = env.split('.')[-1].lower() if env else ''
    hdr_risky = int(hdr_tld in risky_tlds)
    env_risky = int(env_tld in risky_tlds)

    def digit_in(d):
        return int(any(c.isdigit() for c in d.split('.')[0])) if d else 0

    rt_domain = _extract_domain(reply_to)
    reply_mismatch = int(bool(rt_domain) and rt_domain != hdr)

    spam_high      = int(spam_score >= 5.0)
    spam_very_high = int(spam_score >= 8.0)

    arc_fail = int('cv=fail' in arc_seal.lower())
    arc_pass = int('cv=pass' in arc_seal.lower())

    row = {
        'spf_score': spf_score, 'spf_pass': spf_pass,
        'spf_fail': spf_fail, 'spf_softfail': spf_softfail, 'spf_none': spf_none,
        'dkim_score': dkim_score, 'dkim_pass': dkim_pass,
        'dkim_fail': dkim_fail, 'dkim_none': dkim_none,
        'dmarc_result_score': dmarc_result_score,
        'dmarc_policy_score': dmarc_policy_score,
        'dmarc_pass': dmarc_pass, 'dmarc_fail': dmarc_fail_f,
        'dmarc_align_spf': dmarc_align_spf_f,
        'dmarc_align_dkim': dmarc_align_dkim_f,
        'dmarc_both_aligned': dmarc_both_aligned,
        'dmarc_none_align': dmarc_none_align,
        'all_auth_pass': all_auth_pass, 'auth_failures': auth_failures,
        'auth_total_score': auth_total_score,
        'domain_aligned': domain_aligned, 'is_spoofed': is_spoofed,
        'header_domain_len': len(hdr), 'envelope_domain_len': len(env),
        'domain_len_diff': abs(len(hdr)-len(env)),
        'header_domain_risky_tld': hdr_risky,
        'envelope_domain_risky_tld': env_risky,
        'digit_in_header_domain': digit_in(hdr),
        'digit_in_envelope_domain': digit_in(env),
        'hyphen_in_domain': int('-' in hdr),
        'hop_count': hop_count, 'high_hop_count': int(hop_count >= 5),
        'reply_to_mismatch': reply_mismatch,
        'spam_score': spam_score, 'spam_score_high': spam_high,
        'spam_score_very_high': spam_very_high,
        'arc_fail': arc_fail, 'arc_pass': arc_pass,
        'spf_dkim_both_fail': int(spf_fail and dkim_fail),
        'spoofed_and_spammy': int(is_spoofed and spam_high),
        'misalign_dmarc_fail': int(not domain_aligned and dmarc_fail_f),
        'risky_tld_auth_fail': int(hdr_risky and auth_failures > 0),
    }

    # Drop spam_score features -- removed during retraining
    for col in ['spam_score', 'spam_score_high',
                'spam_score_very_high', 'spoofed_and_spammy']:
        row.pop(col, None)

    df = pd.DataFrame([row])
    df = df.reindex(columns=feat_cols, fill_value=0)
    return df


def run_ml_engine(p, rf, xgb_m, le, feat_cols, explainer):
    X = _engineer_features(p, feat_cols)

    rf_prob  = rf.predict_proba(X)[0]
    xgb_prob = xgb_m.predict_proba(X)[0]
    ens_prob = 0.40 * rf_prob + 0.60 * xgb_prob

    classes    = list(le.classes_)
    pred_idx   = int(np.argmax(ens_prob))
    pred_label = classes[pred_idx]

    prob_dict = {c: round(float(ens_prob[i]), 4) for i, c in enumerate(classes)}
    legit_idx = classes.index('legitimate') if 'legitimate' in classes else 0
    ml_score  = round(1.0 - float(ens_prob[legit_idx]), 4)

    top_shap = []
    try:
        sv = explainer.shap_values(X)
        if isinstance(sv, list):
            vals = sv[pred_idx][0]
        elif hasattr(sv, 'ndim') and sv.ndim == 3:
            vals = sv[0, :, pred_idx]
        else:
            vals = sv[0]
        pairs = sorted(zip(feat_cols, vals), key=lambda x: abs(x[1]), reverse=True)
        top_shap = [(n, round(float(v), 4)) for n, v in pairs[:5]]
    except Exception:
        pass

    phish_idx = classes.index('phishing') if 'phishing' in classes else 0

    return {
        'ml_score'          : ml_score,
        'ml_pred_label'     : pred_label,
        'prob_legit'        : prob_dict.get('legitimate', 0),
        'prob_phishing'     : prob_dict.get('phishing',   0),
        'prob_spam'         : prob_dict.get('spam',       0),
        'rf_prob_phishing'  : round(float(rf_prob[phish_idx]),  4),
        'xgb_prob_phishing' : round(float(xgb_prob[phish_idx]), 4),
        'top_shap'          : top_shap,
    }


# ==============================================================
#  LAYER 4  -  HYBRID SCORER + DISPLAY + CSV
# ==============================================================

def _verdict(score):
    if score >= CONFIG['BLOCK_THRESHOLD']:
        return 'BLOCK'
    if score >= CONFIG['QUARANTINE_THRESHOLD']:
        return 'QUARANTINE'
    return 'ALLOW'

def _threat(verdict):
    return {'BLOCK':'HIGH','QUARANTINE':'MEDIUM','ALLOW':'NONE'}.get(verdict,'NONE')

def _label(verdict):
    return {
        'BLOCK'      : 'PHISHING / THREAT DETECTED',
        'QUARANTINE' : 'SUSPICIOUS -- QUARANTINE',
        'ALLOW'      : 'LIKELY LEGITIMATE',
    }.get(verdict, 'LIKELY LEGITIMATE')


def compute_hybrid(rule_r, ml_r):
    s_rule = rule_r['norm_score']
    s_ml   = ml_r['ml_score']

    # Adaptive weights -- trust rules more when they fire strongly
    if rule_r['rule_flagged']:
        w_rule, w_ml = 0.65, 0.35
    else:
        w_rule, w_ml = 0.35, 0.65

    s_hyb = round(w_rule * s_rule + w_ml * s_ml, 4)
    v = _verdict(s_hyb)

    # Safety override -- if rules fired, never allow through
    if rule_r['rule_flagged'] and v == 'ALLOW':
        v = 'QUARANTINE'

    r_flag = rule_r['rule_flagged']
    m_flag = ml_r['ml_score'] >= CONFIG['QUARANTINE_THRESHOLD']

    if   r_flag and m_flag:          agree = 'BOTH AGREE -- THREAT'
    elif not r_flag and not m_flag:  agree = 'BOTH AGREE -- SAFE'
    elif r_flag:                     agree = 'RULE FLAGGED / ML UNCERTAIN'
    else:                            agree = 'ML FLAGGED / RULES CLEAN'

    return {
        'hybrid_score' : s_hyb,
        'rule_score'   : s_rule,
        'ml_score'     : s_ml,
        'verdict'      : v,
        'verdict_label': _label(v),
        'threat_level' : _threat(v),
        'agreement'    : agree,
    }


def print_report(p, rule_r, ml_r, hyb, mode):
    W    = 67
    LINE = '-' * W

    print('=' * W)
    if mode == 'hybrid':
        print("  VERDICT   : " + hyb['verdict_label'])
        print("  THREAT    : " + hyb['threat_level'])
        print("  SCORE     : " + str(hyb['hybrid_score']))
        print("  AGREEMENT : " + hyb['agreement'])
    else:
        print("  VERDICT   : " + hyb['verdict_label'])
        print("  THREAT    : " + hyb['threat_level'])
        print("  SCORE     : " + str(hyb['rule_score']))

    print(LINE)
    print("  FILE    : " + str(p.get('filename', '')))
    print("  FROM    : " + str(p.get('from', '')))
    print("  SUBJECT : " + str(p.get('subject', '')))
    print("  DATE    : " + str(p.get('date', '')))
    print(LINE)
    print("  AUTHENTICATION:")
    print("    SPF   : " + str(p.get('spf_result','?')).ljust(12) +
          "  Domain : " + str(p.get('spf_domain','?')))
    print("    DKIM  : " + str(p.get('dkim_result','?')).ljust(12) +
          "  Signed : " + str(p.get('dkim_signing_domain','?')))
    print("    DMARC : " + str(p.get('dmarc_result','?')).ljust(12) +
          "  Hops   : " + str(p.get('hop_count','?')))
    print(LINE)

    fired = rule_r['fired']
    print("  RULES FIRED (" + str(len(fired)) + "):")
    if fired:
        for rid, pts, src in fired:
            sign = '+' if pts > 0 else ''
            print("    [" + sign + str(pts) + "] " +
                  rid.ljust(30) + "  [" + src + "]")
    else:
        print("    (none)")

    if mode == 'hybrid' and ml_r.get('top_shap'):
        print(LINE)
        print("  ML PREDICTION  : " + ml_r['ml_pred_label'].upper() +
              "  | legit=" + str(ml_r['prob_legit']) +
              "  phish=" + str(ml_r['prob_phishing']) +
              "  spam=" + str(ml_r['prob_spam']))
        print("  TOP SHAP FEATURES:")
        pred = ml_r.get('ml_pred_label', 'legitimate').lower()
        is_threat = pred in ('phishing', 'spam')
        for feat, val in ml_r['top_shap']:
            if is_threat:
                direction = 'toward threat' if val > 0 else 'toward legit'
            else:
                direction = 'toward legit' if val > 0 else 'toward threat'
            print("    " + feat.ljust(34) +
                  "  SHAP=" + ('+' if val >= 0 else '') + str(val) +
                  "  " + direction)

    print('=' * W)
    print('')


def _csv_row(p, rule_r, ml_r, hyb, mode, fname):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    shap_str     = '; '.join(f + '(' + ('+' if v >= 0 else '') + str(v) + ')'
                             for f, v in ml_r.get('top_shap', []))
    fired_names  = '; '.join(r[0] for r in rule_r['fired'])
    fired_detail = '; '.join(r[0] + '(' + ('+' if r[1] >= 0 else '') +
                             str(r[1]) + ')' for r in rule_r['fired'])
    return {
        'filename'         : fname,
        'mode'             : mode,
        'verdict'          : hyb['verdict_label'],
        'threat_level'     : hyb['threat_level'],
        'hybrid_score'     : hyb['hybrid_score'],
        'rule_norm_score'  : rule_r['norm_score'],
        'rule_raw_score'   : rule_r['raw_score'],
        'ml_score'         : ml_r.get('ml_score', ''),
        'ml_pred_label'    : ml_r.get('ml_pred_label', ''),
        'prob_legitimate'  : ml_r.get('prob_legit', ''),
        'prob_phishing'    : ml_r.get('prob_phishing', ''),
        'prob_spam'        : ml_r.get('prob_spam', ''),
        'agreement'        : hyb.get('agreement', ''),
        'spf_result'       : p.get('spf_result', ''),
        'dkim_result'      : p.get('dkim_result', ''),
        'dmarc_result'     : p.get('dmarc_result', ''),
        'domain_aligned'   : p.get('header_from_domain','') == p.get('envelope_from_domain',''),
        'hop_count'        : p.get('hop_count', ''),
        'spam_score'       : p.get('x_spam_score', ''),
        'from'             : p.get('from', ''),
        'return_path'      : p.get('return_path', ''),
        'subject'          : p.get('subject', ''),
        'date'             : p.get('date', ''),
        'rules_fired_count': len(rule_r['fired']),
        'rules_fired_names': fired_names,
        'rule_details'     : fired_detail,
        'top_shap_features': shap_str,
        'timestamp'        : now,
    }


def write_csv(rows, out):
    import csv
    if not rows:
        return
    cols = list(rows[0].keys())
    exists = os.path.isfile(out)
    with open(out, 'a', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        if not exists:
            w.writeheader()
        w.writerows(rows)


# ==============================================================
#  EMAIL PARSER
# ==============================================================

def parse_email(filepath):
    with open(filepath, 'rb') as f:
        raw = f.read()
    try:
        msg = emaillib.message_from_bytes(raw, policy=email_policy.default)
    except Exception:
        msg = emaillib.message_from_bytes(raw)

    p = {'filename': os.path.basename(filepath)}
    p['from']        = str(msg.get('From', '') or '')
    p['return_path'] = str(msg.get('Return-Path', '') or '')
    p['reply_to']    = str(msg.get('Reply-To', '') or '')
    p['subject']     = str(msg.get('Subject', '') or '')
    p['date']        = str(msg.get('Date', '') or '')
    p['header_from_domain']   = _extract_domain(p['from'])
    p['envelope_from_domain'] = _extract_domain(p['return_path'])

    # SPF
    spf_result = 'none'
    spf_domain = ''
    for h in ('Received-SPF', 'Authentication-Results'):
        v = str(msg.get(h, '') or '')
        m = re.search(r'spf\s*=\s*(\S+)', v, re.I)
        if m:
            spf_result = m.group(1).lower().strip('();,')
            m2 = re.search(r'smtp\.mailfrom\s*=\s*([\w.\-@]+)', v, re.I)
            if m2:
                spf_domain = _extract_domain(m2.group(1))
            break
    p['spf_result'] = spf_result
    p['spf_domain'] = spf_domain or p['envelope_from_domain']

    # DKIM
    dkim_result = 'none'
    dkim_domain = ''
    for h in ('Authentication-Results', 'DKIM-Signature'):
        v = str(msg.get(h, '') or '')
        m = re.search(r'dkim\s*=\s*(\S+)', v, re.I)
        if m:
            dkim_result = m.group(1).lower().strip('();,')
            m2 = re.search(r'\bd\s*=\s*([\w.\-]+)', v, re.I)
            if m2:
                dkim_domain = m2.group(1).lower()
            break
    p['dkim_result']         = dkim_result
    p['dkim_signing_domain'] = dkim_domain

    # DMARC
    auth = str(msg.get('Authentication-Results', '') or '')
    dmarc_r   = 'none'
    dmarc_pol = 'none'
    m = re.search(r'dmarc\s*=\s*(\S+)', auth, re.I)
    if m:
        dmarc_r = m.group(1).lower().strip('();,')
    m2 = re.search(r'\bp\s*=\s*(\w+)', auth, re.I)
    if m2:
        dmarc_pol = m2.group(1).lower()
    p['dmarc_result']         = dmarc_r
    p['dmarc_policy']         = dmarc_pol
    p['dmarc_alignment_spf']  = 'pass' if spf_result  == 'pass' else 'fail'
    p['dmarc_alignment_dkim'] = 'pass' if dkim_result == 'pass' else 'fail'

    p['arc_seal']     = str(msg.get('ARC-Seal', '') or '')
    p['hop_count']    = len(msg.get_all('Received') or [])
    spam_raw = str(msg.get('X-Spam-Score', msg.get('X-Spam-Status', '0')) or '0')
    m = re.search(r'[-+]?\d+\.?\d*', spam_raw)
    p['x_spam_score'] = float(m.group()) if m else 0.0
    return p


# ==============================================================
#  MAIN
# ==============================================================

def collect_files(target):
    pt = Path(target)
    if pt.is_file():
        return [str(pt)]
    if pt.is_dir():
        files = []
        for ext in ('*.eml', '*.txt', '*.msg'):
            files.extend(glob.glob(str(pt / ext)))
        return sorted(files)
    return []


def main():
    ap = argparse.ArgumentParser(
        description='Hybrid Email Forensics Analyser -- Rules + ML + SHAP')
    ap.add_argument('target',
        help='Email file (.eml / .txt) or folder')
    ap.add_argument('--mode', choices=['hybrid', 'rule'], default='hybrid',
        help='hybrid (default) = rules + ML  |  rule = rules only')
    ap.add_argument('-o', '--output', default='forensics_report.csv',
        help='Output CSV file (default: forensics_report.csv)')
    ap.add_argument('--model-dir', default=None,
        help='Path to models/ folder (default: models/ beside this script)')
    args = ap.parse_args()

    if args.model_dir:
        model_dir = args.model_dir
    else:
        model_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'models')

    mode = args.mode
    rf = xgb_m = le = feat_cols = explainer = None
    models_ok = False

    if mode == 'hybrid':
        if not ML_AVAILABLE:
            print("WARNING: ML libraries not found.")
            print("Install: pip install numpy pandas joblib shap xgboost scikit-learn")
            print("Falling back to rule-only mode.")
            print('')
            mode = 'rule'
        elif not os.path.isdir(model_dir):
            print("WARNING: Models folder not found: " + model_dir)
            print("Train models in email_security_detector.ipynb first.")
            print("Falling back to rule-only mode.")
            print('')
            mode = 'rule'
        else:
            try:
                print("Loading ML models from  " + model_dir + " ...")
                rf, xgb_m, le, feat_cols, explainer = _load_models(model_dir)
                models_ok = True
                print("Models loaded successfully (RF + XGBoost + SHAP)")
                print('')
            except Exception as e:
                print("WARNING: Model load error: " + str(e))
                print("Falling back to rule-only mode.")
                print('')
                mode = 'rule'

    files = collect_files(args.target)
    if not files:
        print("ERROR: No email files found: " + args.target)
        sys.exit(1)

    print("Found " + str(len(files)) + " email file(s)")
    print("Output: " + args.output)
    print("Mode: " + ('HYBRID -- Rules + ML + SHAP' if mode == 'hybrid' else 'RULE ENGINE ONLY'))
    print('')

    all_rows = []
    for idx, fpath in enumerate(files, 1):
        fname = os.path.basename(fpath)
        print("[" + str(idx) + "/" + str(len(files)) + "] Analysing: " + fname)

        try:
            p = parse_email(fpath)
        except Exception as e:
            print("  ERROR: Parse error: " + str(e))
            print('')
            continue

        rule_r = run_rule_engine(p)

        ml_r = {}
        effective_mode = mode
        if mode == 'hybrid' and models_ok:
            try:
                ml_r = run_ml_engine(p, rf, xgb_m, le, feat_cols, explainer)
            except Exception as e:
                print("  WARNING: ML error: " + str(e) + " -- using rule score only")
                effective_mode = 'rule'

        if effective_mode == 'hybrid' and ml_r:
            hyb = compute_hybrid(rule_r, ml_r)
        else:
            v = _verdict(rule_r['norm_score'])
            hyb = {
                'hybrid_score' : rule_r['norm_score'],
                'rule_score'   : rule_r['norm_score'],
                'ml_score'     : '',
                'verdict'      : v,
                'verdict_label': _label(v),
                'threat_level' : _threat(v),
                'agreement'    : 'N/A',
            }

        print_report(p, rule_r, ml_r, hyb, effective_mode)
        all_rows.append(_csv_row(p, rule_r, ml_r, hyb, effective_mode, fname))

    if all_rows:
        try:
            write_csv(all_rows, args.output)
            print("Report saved: " + args.output +
                  "  (" + str(len(all_rows)) + " record(s))")
            print('')
        except PermissionError:
            alt = args.output.replace('.csv', '_new.csv')
            print("WARNING: " + args.output + " is open in another program.")
            print("Close the file in Excel first, then rerun.")
            print("Saving to: " + alt)
            print('')
            write_csv(all_rows, alt)


if __name__ == '__main__':
    main()
