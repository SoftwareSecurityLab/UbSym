#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Feb 14 10:07:03 2021

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""
import angr,claripy

class _strcat_vul(angr.SimProcedure): 
    def run(self,dst_addr, src_addr): 
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        memcpy = angr.SIM_PROCEDURES['libc']['memcpy']
        
        hist_addr=self.state.history.bbl_addrs.hardcopy
        self.state.globals['block_addr']=hist_addr

        src_len = self.inline_call(strlen, src_addr).ret_expr
        dst_len = self.inline_call(strlen, dst_addr).ret_expr
                
        mem_src=self.state.memory.load(src_addr,10)
        if self.state.solver.symbolic(mem_src) ==False:
            value=self.state.mem[src_addr.to_claripy()].string.concrete.decode('ascii')
            self.state.globals['extra_const'].append(('strcat',dst_len,len(value)))
        else:
             if isinstance(dst_len,angr.state_plugins.sim_action_object.SimActionObject):
                 dst_len=dst_len.to_claripy()
             self.state.globals['extra_const'].append(('strcat',dst_len,src_len))
        self.inline_call(memcpy, dst_addr + dst_len, src_addr,src_len+1)

        return dst_addr
    
  
