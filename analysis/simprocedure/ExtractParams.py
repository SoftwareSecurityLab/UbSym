"""
Created on Sun Feb 14 10:07:03 2021

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""
import angr ,claripy
import numpy as np

class SimExtractParams(angr.SimProcedure):

    def run(self, *args, pointers=None):
        self.state.globals['args']=[]
        for numb,typ in pointers.items():
            argRes=None
            if typ == 'intPointer':
                addr=args[numb-1].ast.args[0]
                argRes=int(np.int32(self.state.mem[addr].long.concrete))
            elif typ == 'charPointer':
                addr = args[numb - 1].to_claripy()
                value=self.state.mem[addr].string.concrete
                if isinstance(value,str):
                    argRes=value
                else:
                    argRes=value.decode('ascii','replace')
                argRes=argRes+'\x00'
            elif typ == 'floatPointer':
                addr=args[numb-1].ast.args[0]
                value=self.state.mem[addr].long.concrete
                tmp_val=claripy.BVV(value,32)
                argRes=tmp_val.raw_to_fp().args[0]
            elif typ == 'doublePointer':
                addr=args[numb-1].ast.args[0] 
                value=self.state.mem[addr].long.concrete 
                tmp_val=claripy.BVV(value,64)
                fp=tmp_val.raw_to_fp()
                argRes=tmp_val.raw_to_fp().args[0]
            elif typ in 'char':
                argRes=chr(args[numb-1].ast.args[0])
            elif typ in 'int':
                val=args[numb-1].ast
                argRes=int(np.int32(self.state.solver.eval(val)))
            elif typ in 'float':
                tmp_val=claripy.BVV(args[numb-1].args[0],32)
                argRes=tmp_val.raw_to_fp().args[0]
            elif typ == "double":
                tmp_val=claripy.BVV(args[numb-1].args[0],64)
                argRes=tmp_val.raw_to_fp().args[0]
            else:
                argRes=args[numb-1]
            self.state.globals['args'].append(argRes)
        self.exit(0)    
        return 0
            
