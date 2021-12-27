import pandas as pd
import numpy as np
import json

vt_engine = pd.read_csv("selection_model/vt_engine.csv",index_col=0)
apicall = pd.read_csv("selection_model/apicall.csv",index_col=0)
individual = pd.read_csv("selection_model/individual.csv",index_col=0)
family = pd.read_csv("selection_model/family.csv",index_col=0)
family_file = json.loads(open("selection_model/family.json").read())
apicall_file = json.loads(open("selection_model/api_call_cluster.json").read())

perturbations = list(individual.columns)

def get_group(h,catelist):
    for key in catelist:
        if h in catelist[key]:
            return key

def individual_selection(cnt):
    temp = (list(individual.loc["total"]))
    total = sum(temp)
    pri = [t/total for t in temp]
    select = np.random.choice(perturbations, cnt, p=pri)

    return select

def apicall_selection(h,cnt):
    group = "cluster"+str(get_group(h,apicall_file))
    temp = (list(apicall.loc[group]))
    total = sum(temp)
    
    pri = [t/total for t in temp]

    select = np.random.choice(perturbations, cnt, p=pri)

    return select

    
def family_selection(h,cnt):
    group = str(get_group(h,family_file))
    temp = (list(family.loc[group]))
    total = sum(temp)
    
    pri = [t/total for t in temp]

    select = np.random.choice(perturbations, cnt, p=pri)

    return select

def vt_engine_selection(dlist, cnt):
    pscore = {}
    for pert in perturbations:
        pscore[pert] = 0
    
    for d in dlist:
        for pert, rate in vt_engine[d].iteritems():
            pscore[pert] += rate

    pertlist = list(pscore.keys())
    score = [pscore[pert] for pert in pertlist]
    total = sum(score)
    pri = [t/total for t in score]
    
    select = np.random.choice(pertlist,cnt,p=pri)

    return select


