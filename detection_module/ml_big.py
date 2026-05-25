import json, math, re, sys, hashlib
from collections import Counter
from pathlib import Path
import numpy as np
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
try: sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass

TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{6,}")
KW = re.compile(r"(?i)secret|passw|pwd|\bpass\b|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|\bauth|credential|otp|salt|nonce|bearer|\bkey\b")
NEG = re.compile(r"(?i)getenv|environ|process\.env|os\.environ|config\(|settings\.|example|placeholder|your[_-]|changeme|dummy|sample|\btest\b")
PREFIX = re.compile(r"AKIA|ASIA|gh[pousr]_|sk-|AIza|xox[baprs]-|glpat-|github_pat_|SG\.|npm_|dop_v1_|hvs\.|sk_live_|sk_test_|eyJ|glsa_|dapi|ATATT")
HEX = re.compile(r"\A[0-9a-fA-F]+\Z")
B64 = re.compile(r"\A[A-Za-z0-9+/=_\-]+\Z")
UUID = re.compile(r"(?i)\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")

def entropy(s):
    if not s: return 0.0
    n=len(s); return -sum((c/n)*math.log2(c/n) for c in Counter(s).values())

def cand(line):
    t=TOKEN.findall(line); return max(t, key=lambda x:(round(entropy(x),2),len(x))) if t else ""

def numfeats(line):
    c=cand(line); L=max(1,len(c))
    return [len(line), len(c), entropy(c), entropy(line),
            sum(ch.isdigit() for ch in c)/L, sum(ch.isupper() for ch in c)/L,
            sum(not ch.isalnum() for ch in c)/L,
            int(any(x.islower() for x in c) and any(x.isupper() for x in c) and any(x.isdigit() for x in c)),
            int(bool(KW.search(line))), int(bool(NEG.search(line))), int(bool(PREFIX.search(line))),
            int("=" in line or ":" in line), line.count('"')+line.count("'"),
            int(bool(HEX.match(c)) and len(c) in (32,40,64)), int(bool(UUID.match(c))),
            int(bool(B64.match(c)) and len(c)>=24), line.find(c)/max(1,len(line))]

def prf(y,p):
    tp=sum(1 for a,b in zip(y,p) if a and b); fp=sum(1 for a,b in zip(y,p) if b and not a); fn=sum(1 for a,b in zip(y,p) if a and not b)
    P=tp/(tp+fp) if tp+fp else 0; R=tp/(tp+fn) if tp+fn else 0
    return P,R,(2*P*R/(P+R) if P+R else 0)

def best(y,proba,name):
    bF=0;bt=0.5;bp=br=0
    for thr in [i/100 for i in range(20,90,5)]:
        P,R,F=prf(y,[int(x>=thr) for x in proba])
        if F>bF: bF,bt,bp,br=F,thr,P,R
    print(f"  {name:20s} best F1={bF:.3f} (thr={bt}, P={bp:.3f} R={br:.3f})")
    return bF

rows=[json.loads(l) for l in Path("creddata.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
def grp(r): return int(hashlib.md5(r.get("repo","?").encode()).hexdigest(),16)%5
tr=[r for r in rows if grp(r)!=0]; te=[r for r in rows if grp(r)==0]
ytr=[r["label"] for r in tr]; yte=[r["label"] for r in te]
print(f"train={len(tr)} test={len(te)} | репо train/test={len({r['repo'] for r in tr})}/{len({r['repo'] for r in te})}")

ct=TfidfVectorizer(analyzer="char_wb", ngram_range=(2,5), max_features=3000, min_df=3)
cl=TfidfVectorizer(analyzer="char_wb", ngram_range=(3,5), max_features=2000, min_df=3)
wl=TfidfVectorizer(analyzer="word", ngram_range=(1,2), max_features=1500, min_df=3, token_pattern=r"[A-Za-z_]{2,}")
Xtr_ct=ct.fit_transform([cand(r["text"]) for r in tr]); Xte_ct=ct.transform([cand(r["text"]) for r in te])
Xtr_cl=cl.fit_transform([r["text"] for r in tr]);       Xte_cl=cl.transform([r["text"] for r in te])
Xtr_wl=wl.fit_transform([r["text"] for r in tr]);       Xte_wl=wl.transform([r["text"] for r in te])
Ntr=np.array([numfeats(r["text"]) for r in tr],float);  Nte=np.array([numfeats(r["text"]) for r in te],float)
mu,sd=Ntr.mean(0),Ntr.std(0)+1e-9
Xtr=hstack([csr_matrix((Ntr-mu)/sd),Xtr_ct,Xtr_cl,Xtr_wl]).tocsr()
Xte=hstack([csr_matrix((Nte-mu)/sd),Xte_ct,Xte_cl,Xte_wl]).tocsr()

print("\n=== модели (repo-disjoint test) ===")
lr=LogisticRegression(class_weight="balanced",max_iter=4000,C=6.0).fit(Xtr,ytr)
plr=lr.predict_proba(Xte)[:,1]; best(yte,plr,"LogReg (rich text)")

gb=HistGradientBoostingClassifier(max_iter=400,learning_rate=0.08,max_leaf_nodes=63,
      class_weight="balanced",validation_fraction=0.1).fit((Ntr-mu)/sd,ytr)
pgb=gb.predict_proba((Nte-mu)/sd)[:,1]; best(yte,pgb,"HistGBM (numeric)")

pens=0.5*plr+0.5*pgb; best(yte,pens,"Ансамбль LR+GBM")
