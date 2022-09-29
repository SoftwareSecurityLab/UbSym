#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Feb 14 10:07:03 2021

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""
import angr,claripy

class _memset_vul(angr.SimProcedure): 
    def run(self, dst_addr, char, num): 
        memset = angr.SIM_PROCEDURES['libc']['memset']
        hist_addr=self.state.history.bbl_addrs.hardcopy
        self.state.globals['block_addr']=hist_addr        
        
        if self.state.solver.symbolic(num) ==False:
            self.state.globals['extra_const'].append(('memset',self.state.solver.eval(num.to_claripy())))
        else:
            self.state.globals['extra_const'].append(('memset',num.to_claripy()))
            
        
        self.inline_call(memset,dst_addr,char,num)
        return dst_addr
    

