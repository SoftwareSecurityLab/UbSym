#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Feb 13 22:07:00 2021

@author: Sara Baradaran, Mahdi Heidari, Ali Kamal
"""
import angr,claripy

class _memmove_vul(angr.SimProcedure): 
    def run(self,dst_addr, src_addr ,limit): 
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        memcpy = angr.SIM_PROCEDURES['libc']['memcpy']
        
        hist_addr=self.state.history.bbl_addrs.hardcopy
        self.state.globals['block_addr']=hist_addr
        
        if self.state.solver.symbolic(limit) ==False:
            limit=self.state.solver.eval(limit.to_claripy())
        else:
            limit=limit.to_claripy()

        con_res=['memmove',limit]
            
        self.state.globals['extra_const'].append(tuple(con_res))
        
        self.inline_call(memcpy, dst_addr, src_addr,limit)

        return dst_addr
