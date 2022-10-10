"""
Created on Sun Feb 14 10:07:03 2021

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""
import angr,claripy

class ExeFunc(angr.SimProcedure):
    def run(*argv):
        pass
        #return claripy.BVS('UNConstrainRetValue',8)
