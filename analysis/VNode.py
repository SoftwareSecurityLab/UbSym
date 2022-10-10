#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Sep 11 23:39:17 2020

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""
class _VNode:
    def __init__(self,inode=None,addr=None,block=None,constraints=None,parent_addr=None,satisfiable=False):
        if block is None:
            self.blocks=[]
        else:
            self.blocks=[block]
        
        if constraints is None:
            self.constraints=[]
        else:      
            self.constraints=constraints
        self.addr=addr
        self.Term=[]
        self.V=[]
        self.v=[]
        self._called=[]
        self.inode=inode
        self._has_child=False
        self._parent_addr=parent_addr
        self._satisfiable=satisfiable
        self._vul_susp=False
        self._extra_vul_const=[]
        self._vulMsg=[]
        self._stack={}
        
    def _setUpStack(self,stack_values,parent={}):
        if len(parent) > 0:
            self._stack=parent.copy()
        for addr,value in stack_values:
            self._stack[addr]=value
            
        
    def _correctStack(self,new_stack):
       for addr,value in new_stack.items():
           self._stack[addr]=value
       
    def isEqual(self,other,isEntryLoop=False):
        
        if isEntryLoop:
            if self.addr == other.addr:
                return True
        
        if self._parent_addr != other._parent_addr:
            return False
        
        
        if self.addr != other.addr:
            return False
        
            
            
        return True
        

        
    def addVulMessage(self,mesg):
        self._vulMsg.append(mesg)
        
        
    def setSatisfaiablilyStatus(self,status):
        self._satisfiable=status
        
    def setVulSusp(self,value):
        self._vul_susp=value

    def addVulConstraint(self,constraint):
        self._extra_vul_const.append(constraint)
        
        
    def addSystemIn(self,V):
        self.V.append(V)
    
    def _addCallee(self,addr):
        self._called.append(addr)
        
    def addUnitIn(self,v):
        self.v.append(v)
        
    def checkISINParent(self,item_con,parent_cons):
        for item in parent_cons:
            if item_con is item:
                return True
        return False
    
    def addConstraints(self,consts,parent):
        self.constraints=consts
        for item in self.constraints:
            if self.checkISINParent(item,parent.constraints) == False:
                self.Term.append(item)
                
        for item in parent.constraints:
            if self.checkISINParent(item,self.constraints) == False:
                self.constraints.append(item)



    def addBlock(self,addr):
        self.blocks.append(addr)
        
    @classmethod
    def getNodeNumber(cls):
        return cls.inode
    
    def pp(self):
        content='Node-{0}\nConstraints: {1}\nUnitInputs: {2}\nSystemInputs: {3}\nBasicBlocks Addr: {4}\nCallees: {5}\n'.format(self.inode,self.constraints,self.v,self.V,self.blocks,self._called)
        print(content)
       
    def __str__(self):
        return 'Node-{0}'.format(self.inode)
        






