#!/usr/bin/env python3

import argparse
import claripy,angr,monkeyhex
from analysis.CFGPartAnalysis import CFGPartAnalysis
from analysis.simprocedure.vul_strcat import _strcat_vul
from analysis.InitRun import InitRun
from analysis.VTree import _VTree
from analysis.VulAnalyzer import VulAnalyzer

#               0   ,  1  ,  2  ,  3
CHECK_TYPE = ["HOF", "SOF", "DF", "UAF"]

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b","--binary",help="The Name of Binary File You Want to Analyze",required=True)
    parser.add_argument("-t","--type", help="UbSym's type", choices=CHECK_TYPE, default="HOF")
    parser.add_argument("-p","--prototype",help="The Prototype of Test Unit You Want to Analyze",required=False)
    parser.add_argument("-a","--args",help="The Size of Test Unit Arguments",required=False)
    parser.add_argument("-s","--sizes",help="The Indexes of Argv Passed to The Test Unit As Function Arguments",required=False)
    parser.add_argument("-S","--solo", help="VTree solo mode if disable dive into inner functions", action='store_true', default=False, required=False)
    args = parser.parse_args()

    args_index=[]
    if  args.args :
        args_index=list(map(int,args.args.split(',')))

    args_sizes=[]
    if args.sizes :
        args_sizes=list(map(int,args.sizes.split(',')))

    flag=True
    if args.prototype is None:
        flag=False
    
    checkType = CHECK_TYPE.index(args.type)
    
    proj=angr.Project(args.binary,load_options={'auto_load_libs':False})
    angr.AnalysesHub.register_default('CFGPartAnalysis',CFGPartAnalysis)
    angr.AnalysesHub.register_default('VTree',_VTree)
    angr.AnalysesHub.register_default('VulAnalyzer',VulAnalyzer)
    cfg_an=proj.analyses.CFGPartAnalysis() 
    an=proj.analyses.VulAnalyzer(cfg_an, checkType, args.solo)
    
    
    if flag:
        if checkType < 2 :
            an.overflowAnalyze(args.prototype,args_index=args_index,arg_sizes=args_sizes,buff_type=checkType)
        else :
            an.analyze(args.prototype,args_index=args_index,arg_sizes=args_sizes,VulnType=checkType)
    else:
        if checkType < 2 :
            an.propOverflowUnits()
        else :
            an.propWUnits()
