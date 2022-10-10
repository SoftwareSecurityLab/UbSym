#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Dec 21 18:14:17 2020

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""

from analysis.MCSimulation import MCSimulation
from analysis.MallocExtractParam import mallocEx
from analysis.TypeUtils import *

class InitRun:
    def __init__(self,project,mc_config,cfg_analyses,target_func=None):
        self.project=project
        self.project.hook_symbol('malloc',mallocEx(num_args=1)) 
        self.target_func=target_func
        self.cfg_analyses=cfg_analyses
        self.malloc_points=[]
        self.mc=MCSimulation(config_file=mc_config)
        for addr,func in self.cfg_analyses.getAddressOfFunctionCall('malloc'):
            if self.cfg_analyses.isReachableFromMain(func.name):
                self.malloc_points.append((addr,func))
  

    
    def run(self,args_index=[]):
        flag=True
        res=None
        while flag:
            inSample = self.mc.generate(count=1)[0]
            inputs=[]
            
            for i in range(len(inSample)):
                tp=self.mc.getVarTypes(i)
                if 'int' in tp:
                    inputs.append(getIntConcreteBV(int(inSample[i])))
                elif isinstance(tp,tuple) and 'char*' in tp[0]:
                    inputs.append(getCharStringConcreteBV(inSample[i][0:20]))
                else:
                    inputs.append(getCharStringConcreteBV(inSample[i]))
            argss=[]        
            if len(args_index) > 0:
                argss.append(self.project.filename)
                for indx in args_index:
                    argss.append(inputs.pop(indx-1))
                state=self.project.factory.entry_state(args=argss,stdin=angr.SimPacketsStream(name='stdin', content=inputs,),add_options=angr.options.unicorn)                       
            else:
                state=self.project.factory.entry_state(stdin=angr.SimPacketsStream(name='stdin', content=inputs,),add_options=angr.options.unicorn)
            state.libc.buf_symbolic_bytes=100
            simgr=self.project.factory.simulation_manager(state)
            simgr.explore(find=self._explore_states)
            
            res=dict(simgr.deadended[0].globals)
            if len(self.malloc_points) == len(res):
                flag=False
        return res
            
        
    def _explore_states(self,state):
        for addr,func in self.malloc_points:
            if addr in state.block().instruction_addrs:
                state.globals[addr]=None
        return False




