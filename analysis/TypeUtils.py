#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jan  5 17:05:32 2021

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""


import claripy,angr,binascii
import time,numpy

def integerEncoding(value):
    if value > 0:
        val=str(value)
        lenght=10-len(val)
        return bytes('0'*lenght + val,encoding='utf-8')
    else:
        return bytes(str(2**32 + value),encoding='utf-8')
    
    
def getTwoComp(val, bits):
    if (val & (1 << (bits - 1))) != 0: 
        val = val - (1 << bits)        
    return val        


def getIntConcreteBV(value):
    return claripy.BVV(integerEncoding(value))

def getCharStringConcreteBV(value):
    return claripy.BVV(value)

def getSymbolicBV(var_name,tp,size=None,exp_name=True):
    if size is not None:
        bit=claripy.BVS(var_name,size*8,explicit_name=exp_name)
        return bit
    elif 'int' in tp:
        bit=claripy.BVS(var_name,32,explicit_name=exp_name)
    elif 'float' in tp:
        bit=claripy.FPS(var_name,claripy.FSORT_FLOAT,explicit_name=exp_name) 
    elif 'double' in tp:
        bit=claripy.FPS(var_name,claripy.FSORT_DOUBLE,explicit_name=exp_name) 
    elif  'char' in tp:
        bit=claripy.BVS(var_name,8,explicit_name=exp_name)
   
    if 'Pointer' in tp:
        return angr.PointerWrapper(bit)
    
    return bit
        

def intWiden(opr,value):
    if '64to32' in opr  or '64Sto32' in opr:
        return int(numpy.int32(value))
    elif  '32Uto64' in opr:
        return int(numpy.uint64(value))
    elif '32to64' in opr or '32Sto64' in opr:
        return int(numpy.int64(value))
    elif '64Uto32' in opr:
        return int(numpy.uint32(value))    
    
    
def bino(op,val1,val2):
    if 'Iop_Shl' in op:
        return val1 * 2**val2
    elif 'Iop_Sub' in op:
        return val1 - val2
    elif 'Iop_Add' in op:
        return val1 + val2
    elif 'Iop_Shr' in op:
        return val1 / val2

def reportVul(msg,*ftmt):
    message=msg.format(*ftmt)
    print("\033[0m\033[91m{} \033[91m\033[0m".format(message))

     
def reportBlue(msg,*ftmt):
    message=msg.format(*ftmt)
    print("\033[0m\033[94m{} \033[94m\033[0m".format(message))

    
    
def reportBlack(msg,*ftmt):
    message=msg.format(*ftmt)
    print("\033[0m{} \033[0m".format(message))

    
def reportBold(msg,*ftmt):
    message=msg.format(*ftmt)
    print("\033[0m\033[1m{} \033[1m\033[0m".format(message))

  
def getOprOverBV(bv):
    opr=[]
    if bv.depth > 100:
        return opr
    for i in bv.recursive_children_asts:
        if i.op not in ['BVV','BVS','Extract']:
            opr.append(i.op)
    return opr
   
def _includeOpr(const):
    req_opr=['__or__', '__xor__', '__sub__', '__and__', '__xor__', '__sub__', 'If', '__eq__', '__sub__']
    active=req_opr.pop(0)
    for item in getOprOverBV(const) :
        if item == active:
            if len(req_opr) > 0:
                active=req_opr.pop(0) 
            elif len(req_opr) == 0:
                return True


    req_opr=['SLT', 'ULT', 'SGT', 'UGT', 'SLE', 'ULE', 'SGE', 'UGE','__ne__','__ne__']
    if const.op in req_opr and len(const.args) == 2:
        if isinstance(const.args[1],claripy.ast.bv.BV) and const.args[1].concrete:
            value=const.args[1]
        else:
            value=const.args[0]
        if isinstance(value,claripy.ast.bv.BV):
            value=value.args[0]
        if value in range(33,127):
            return True

    return False
        
def getInterstingIndexes(cost,var_names):

    chosen_list=[]
    for item in cost:
        if isIncludeVarName(item,var_names):
            if _includeOpr(item):
                chosen_list.append(item)
    
    indexes=[]
    for ch_item in chosen_list:
        items=list(ch_item.children_asts())
        for idx in range(len(items)):
            item=items[idx]
            if item.depth == 2 and item.op == 'Extract':
                bv_size=item.args[2]
                var_name=list(bv_size.variables)[0]
                if var_name in var_names:
                    res=(var_name,int(((bv_size.size()-item.args[0])-1)/8))
                    if res not in indexes:
                        indexes.append(res)

    return indexes

def isIncludeVarName(const,var_names):
    for tmp_var in const.variables :
        if tmp_var in var_names:
            return True
    return False

def castTO(e, solution, cast_to):
        """
        copy_from :
            https://github.com/angr/angr/blob/master/angr/state_plugins/solver.py
        Casts a solution for the given expression to type `cast_to`.
        :param e: The expression `value` is a solution for
        :param value: The solution to be cast
        :param cast_to: The type `value` should be cast to. Must be one of the currently supported types (bytes|int)
        :raise ValueError: If cast_to is a currently unsupported cast target.
        :return: The value of `solution` cast to type `cast_to`
        """
        if cast_to is None:
            return solution

        if type(solution) is bool:
            if cast_to is bytes:
                return bytes([int(solution)])
            elif cast_to is int:
                return int(solution)
        elif type(solution) is float:
            solution = _concrete_value(claripy.FPV(solution, claripy.fp.FSort.from_size(len(e))).raw_to_bv())

        if cast_to is bytes:
            if len(e) == 0:
                return b""
            return binascii.unhexlify('{:x}'.format(solution).zfill(len(e)//4))

        if cast_to is not int:
            raise ValueError("cast_to parameter {!r} is not a valid cast target, currently supported are only int and bytes!".format(cast_to))

        return solution
        
        
        
        
        
