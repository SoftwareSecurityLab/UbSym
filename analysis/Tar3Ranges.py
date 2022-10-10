#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Nov  1 19:12:42 2020

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""

from collections import Counter

class Range:
    
    def __init__(self):
        self.var_names=[]
        self.bound={}
        
    def addRange(self,reng):
        for var_name,bnd in reng:
            self.var_names.append(var_name)
            self.bound[var_name]=bnd
            
    def correctBounds(self,reng):
        for var_name,bnd in reng:
            bound=self.bound[var_name]
            old_upper=float(bound[1])
            old_lower=float(bound[0])
            new_upper=float(bnd[1])
            new_lower=float(bnd[0])
            
            if new_upper > old_upper and new_lower >= old_upper:
                bound[1]=new_upper
            elif new_upper <= old_lower and new_lower < old_lower :
                bound[0]=new_lower
            else:
                if new_upper < old_upper : 
                    bound[1]=str(new_upper)
                if new_lower > old_lower :
                    bound[0] = str(new_lower)
            
    def isMatch(self,var_names):
        return Counter(var_names) == Counter(self.var_names)

    def pp(self):
        content=''
        for name in self.var_names:
            if content == '':
                content='{0}:{1}'.format(name,self.bound.get(name))
            else:
                content=content+' And {0}:{1}'.format(name,self.bound.get(name))
        print(content)

