#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Feb 14 10:07:03 2021

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""
import angr

class wcslen(angr.SimProcedure): 
    def run(self, s): 
        print('in wcslen')
        f=angr.SIM_PROCEDURES['libc']['strlen'] 
        self.state.globals['iswchar']=True
        re = self.inline_call(f,s,wchar=True).ret_expr 
        return re
