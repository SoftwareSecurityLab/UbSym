#!/usr/bin/env python3


import argparse
import claripy,angr,monkeyhex
from analysis.CFGPartAnalysis import CFGPartAnalysis
from analysis.simprocedure.vul_strcat import _strcat_vul
from analysis.InitRun import InitRun
from analysis.VTree import _VTree
from analysis.VulAnalyzer import VulAnalyzer
	
import sys, os
sys.setrecursionlimit(2000)

for i in  range(153, 226):
    print('===================')
    print("| Program No.: " + str(i))
    print('===================')
    proj=angr.Project('./tests/' + str(i),load_options={'auto_load_libs':False})
    angr.AnalysesHub.register_default('CFGPartAnalysis',CFGPartAnalysis)
    angr.AnalysesHub.register_default('VTree',_VTree)
    angr.AnalysesHub.register_default('VulAnalyzer',VulAnalyzer)
    cfg_an=proj.analyses.CFGPartAnalysis()
    if   (i >= 1   and i <= 90 ):
        checkType = 0
    elif (i >= 119 and i <= 206):
        checkType = 1
    elif (i >= 91  and i <= 118):
        checkType = 2
    elif (i >= 207 and i <= 225):
        checkType = 3

    an=proj.analyses.VulAnalyzer(cfg_an, checkType, False)
    if   (i >= 1   and i <= 90 ): 
        u = an.propOverflowUnits("HOF")
    elif (i >= 119 and i <= 206):
        u = an.propOverflowUnits("SOF")
    else:
        u = an.propWUnits()

    for unit in u:
        print("Test Unit : <{}>".format(unit))
        proj=angr.Project('./tests/' + str(i),load_options={'auto_load_libs':False})
        angr.AnalysesHub.register_default('CFGPartAnalysis',CFGPartAnalysis)
        angr.AnalysesHub.register_default('VTree',_VTree)
        angr.AnalysesHub.register_default('VulAnalyzer',VulAnalyzer)
        cfg_an=proj.analyses.CFGPartAnalysis()
        if   (i >= 150 and i <= 152):
            an=proj.analyses.VulAnalyzer(cfg_an, checkType, False, 100, 180)
        elif (i >= 153 and i <= 172):
            an=proj.analyses.VulAnalyzer(cfg_an, checkType, False, 180, 180)
        else:
            an=proj.analyses.VulAnalyzer(cfg_an, checkType, False, 120, 130)

        if i in [12, 14, 15, 31, 33, 35, 51, 53, 55, 87, 89, 90, 133, 134, 135, 150, 151, 152, 162, 172, 187, 188, 189, 204, 205, 206]:
            prototype = 'void ' + unit + '(char*, char*)'
            size = [0,180]
        else:
            prototype = 'void ' + unit + '(char*)'
            size = [180]
        if checkType < 2 :
            an.overflowAnalyze(prototype,args_index=[1],arg_sizes=size,buff_type=checkType)
        else :
            an.analyze(prototype,args_index=[1],arg_sizes=size,VulnType=checkType)
        print('\n\n')






