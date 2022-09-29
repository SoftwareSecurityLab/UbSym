#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Dec 14 18:08:03 2020

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""

import angr

class mallocEx(angr.SimProcedure): 
    def run(self,arg,count=None): 
        f=angr.SIM_PROCEDURES['libc']['malloc'] 
        re = self.inline_call(f,arg).ret_expr 
        values=[]
        for addr,size in self.state.globals.items():
            if size is None:
                values.append((addr,arg.to_claripy()))
        for addr,value in values :
            self.state.globals[addr]=self.state.solver.eval(value,cast_to=int)
        if (count is not None) and  (len(self.state.globals.keys()) == count):
            self.exit(1)
        return re

