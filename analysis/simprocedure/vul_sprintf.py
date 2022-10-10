#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Feb 14 10:07:03 2021

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""
from angr.procedures.stubs.format_parser import FormatParser
import angr,claripy

class _sprintf_vul(FormatParser):
    def run(self, dst_ptr):
        fmt_str = self._parse(1)
        out_str = fmt_str.replace(2, self.arg)
        
        hist_addr=self.state.history.bbl_addrs.hardcopy
        self.state.globals['block_addr']=hist_addr
        if self.state.solver.symbolic(out_str) ==False:
            value=self.state.solver.eval(out_str,cast_to=bytes).decode('ascii')
            self.state.globals['extra_const'].append(('sprintf',value))
            
        self.state.memory.store(dst_ptr, out_str)

        self.state.memory.store(dst_ptr + (out_str.size() // 8), self.state.solver.BVV(0, 8))

        return self.state.solver.BVV(out_str.size()//8, self.state.arch.bits)
    
   
