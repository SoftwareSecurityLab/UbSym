# -*- coding: utf-8 -*-
"""
Created on Sat Sep 12 10:41:15 2020

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""

BUF_SYMBOLIC_BYTES=100
MAX_STR_LEN=100

import angr,pyvex,claripy
import networkx as nx
from .VNode import _VNode
from analysis.simprocedure.vul_strcpy import _strcpy_vul
from analysis.simprocedure.vul_strncpy import _strncpy_vul
from analysis.simprocedure.vul_strcat import _strcat_vul
from analysis.simprocedure.vul_strncat import _strncat_vul
from analysis.simprocedure.vul_memcpy import _memcpy_vul
from analysis.simprocedure.vul_memmove import _memmove_vul
from analysis.simprocedure.vul_memset import _memset_vul
from analysis.simprocedure.vul_sprintf import _sprintf_vul
from analysis.simprocedure.UnConstraintRetValue import ExeFunc
from analysis.simprocedure.wcslen import wcslen
import logging
from analysis.TypeUtils import *
import re 

class _VTree(angr.Analysis):
    def __init__(self,cfg_analyzer=None,solo=True):
        logging.disable(logging.CRITICAL)
        self._graph=nx.DiGraph()
        self._root=None
        self._func=None
        self._inode=0
        self._allvars=[]
        self._is_static_vul=False
        self._func_heap_wr_sites={}
        self._func_stack_wr_sites={}
        self._heap_wr_sites=[]
        self._stack_wr_sites=[]
        self._malloc_boundry=None
        self._malloc_args=None
        self.cfg_Analyzer=cfg_analyzer
        self._init_hook()
        self._vulReports=[]
        self._vulConstNumb=0
        self._generetedVulConst={}
        self._loopsAddrs=[]
        self._loopentries=[]
        self._loop_breadedges=[]
        self._loopsFirstNodes=[]
        self._loopTerm=None
        self._malloc_relativeAddr={}
        self._stack_relativeAddr={}
        self._activeWRmalloc_bnd={}
        self._argv={}
        self._solo=solo
        self.PointerNum = 0
        self.WFreeaddrs = {}
    

    def _init_hook(self):
        self.project.hook_symbol('wcslen',wcslen())
        self.project.hook_symbol('strcpy',_strcpy_vul())
        self.project.hook_symbol('strncpy',_strncpy_vul())
        self.project.hook_symbol('strcat',_strcat_vul()) 
        self.project.hook_symbol('strncat',_strncat_vul()) 
        self.project.hook_symbol('memcpy',_memcpy_vul())
        self.project.hook_symbol('memmove',_memmove_vul())
        self.project.hook_symbol('memset',_memset_vul())
        self.project.hook_symbol('sprintf',_sprintf_vul())
        
    def setupWFreeArgs(self,PointerNum, WFreeaddrs):
        #print(f"[!] setupWFreeArgs: PointerNum: {PointerNum} and ")
        #for addr, addrStatus in WFreeaddrs.items():
            #print(f"\t{hex(addr)} : {addrStatus}")
        self.PointerNum = PointerNum
        self.WFreeaddrs = WFreeaddrs
        

    def setupArgv(self,argv):
        self._argv=argv
    
    
    def _rehooking(self):
        self.project.hook_symbol('wcslen',angr.SIM_PROCEDURES['libc']['strlen']())
        self.project.hook_symbol('strcpy',angr.SIM_PROCEDURES['libc']['strcpy']())
        self.project.hook_symbol('strncpy',angr.SIM_PROCEDURES['libc']['strncpy']())
        self.project.hook_symbol('strcat',angr.SIM_PROCEDURES['libc']['strcat']())
        self.project.hook_symbol('strncat',angr.SIM_PROCEDURES['libc']['strncat']())
        self.project.hook_symbol('memcpy',angr.SIM_PROCEDURES['libc']['memcpy']())
        self.project.hook_symbol('memset',angr.SIM_PROCEDURES['libc']['memset']())
        self.project.hook_symbol('memmove',angr.SIM_PROCEDURES['libc']['memcpy']())
        self.project.hook_symbol('sprintf',angr.SIM_PROCEDURES['libc']['sprintf']())
        
    
    
    def setUpMallocRelativeAddr(self,address):
        for m_addr,records in address:
            self._malloc_relativeAddr[m_addr]=(claripy.BVV(records[1].con.value,64),records[2])
            
                
    def setUpStackBufferRelativeAddr(self,address):
        for m_addr,records in address:
            self._stack_relativeAddr[m_addr]=(claripy.BVV(records[1].con.value,64),records[2]) 
                       
    
    def sefValspHeap(self,address):
        for addr,wr_list in address:
            if isinstance(wr_list,tuple):
                func,cb_addr,tp = wr_list
                if cb_addr not in self._func_heap_wr_sites.keys():
                    self._func_heap_wr_sites[cb_addr]=[func,(addr,tp)]
                else:
                    tmp_res=(addr,tp)
                    if tmp_res not in self._func_heap_wr_sites.get(cb_addr):
                        self._func_heap_wr_sites.get(cb_addr).append((addr,tp))
            else:
                self._heap_wr_sites.append((addr,wr_list))
                
    def sefValspStack(self,address):
        for addr,wr_list in address:
            if isinstance(wr_list,tuple):
                func,cb_addr,tp = wr_list
                if cb_addr not in self._func_stack_wr_sites.keys():
                    self._func_stack_wr_sites[cb_addr]=[func,(addr,tp)]
                else:
                    tmp_res=(addr,tp)
                    if tmp_res not in self._func_stack_wr_sites.get(cb_addr):
                        self._func_stack_wr_sites.get(cb_addr).append((addr,tp))
            else:
                self._stack_wr_sites.append((addr,wr_list))

    def setMallocArgs(self,malloc_args):
        self._malloc_args=malloc_args
            
    def setMallocBoundry(self,boundry):
        self._malloc_boundry=boundry
        
    def setStackBoundry(self,boundry):
        self._stack_boundry=boundry
    
    def _getVariableByName(self,name):
        for var in self._allvars:
            if name in var.variables:
                return var
            
        return None
    
    def _preparingSoloMode(self):
        start=self._func.startpoint.addr
        end=self.cfg_Analyzer.getEndPoint(self._func.name)
        
        for addr,func_name in self.cfg_Analyzer.remvoeSTLFunctionInList(self.cfg_Analyzer.getFunctionCalledBetweenBoundry(self._func.name,start,end)):
            self.project.hook_symbol(func_name,ExeFunc())
            
    def _clearSoloNodeEffect(self):
        start=self._func.startpoint.addr
        end=self.cfg_Analyzer.getEndPoint(self._func.name)
        
        for addr,func_name in self.cfg_Analyzer.remvoeSTLFunctionInList(self.cfg_Analyzer.getFunctionCalledBetweenBoundry(self._func.name,start,end)):
            self.project.unhook_symbol(func_name)
    
    def getVarNames(self):
        var_names=[]
        for var in self._allvars:
            name=list(var.variables)[0]
            var_names.append(name)
        return var_names
    
    def generateForCallable(self,func,*args,loop_bound=100,VulnType):
        self._func=func      
        if self._solo:
            self._preparingSoloMode()
        for arg in args:
            if isinstance(arg,angr.calling_conventions.PointerWrapper):
                self._allvars.append(arg.value)
            else:
                self._allvars.append(arg)
                
        self._state=self.project.factory.call_state(func.addr,*args,add_options={angr.options.TRACK_CONSTRAINTS})
        self._state.libc.buf_symbolic_bytes=BUF_SYMBOLIC_BYTES
        self._state.libc.max_str_len=MAX_STR_LEN
        self._state.globals['extra_const']=[]
        self._simgr=self.project.factory.simulation_manager(self._state)
        self._simgr.use_technique(angr.exploration_techniques.DFS())
                
        self.anloops=self.project.analyses.LoopFinder(functions=[self._func]) 
        if len(self.anloops.loops) > 0:
            cfg = self.project.analyses.CFGFast(normalize=True)
            self._simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions=func.name,use_header=True, bound=loop_bound,bound_reached=self.bnd_reached))
            for loop in self.anloops.loops:
                self._setLoopsBound(loop)
                self._loopentries.append(loop.entry.addr)
                self._extractLoopFirstNode(loop)
                for en , ex in loop.break_edges:
                    self._loop_breadedges.append((en.addr,ex.addr))

        end=self.cfg_Analyzer.getEndPoint(self._func.name)
        self.NodeStatus=None
        extConst = VulnType < 2
        while len(self._simgr.active) > 0 :
            act_state=self._simgr.active[0]
            vul_const=None
            
            if extConst and len(act_state.globals['extra_const'])>0:
                rhs=act_state.globals['extra_const'].pop();
                target_call_hist=self._correctHistory( act_state.globals['block_addr'] )
                
                target_block_addr = target_call_hist[-1]
                target_vul_state=self.cfg_Analyzer.getBlockRelatedToAddr(target_block_addr)
                curr_wfCall=target_vul_state.instruction_addrs[-1]
                iswchar=False
                if 'iswchar' in act_state.globals.keys() and act_state.globals['iswchar']==True:
                    iswchar=True

                if VulnType == 0 :
                    vul_const=self.setUpHeapVulConstraints(target_vul_state.vex,curr_wfCall,rhs,target_call_hist,'heap',iswchar)
                elif VulnType == 1 :
                    vul_const=self.setUpStackVulConstraints(target_vul_state.vex,curr_wfCall,rhs,target_call_hist,'stack',iswchar)
               
            self._collect(act_state,True,VulnType,extra_const=vul_const)
            if act_state.addr == end :
                self.NodeStatus=None
            self._simgr.step()
              
                
        #re_hooking
        self._rehooking()
        if self._solo:
            self._clearSoloNodeEffect()
        
        return self._graph
    
    
    def bnd_reached(self,seer,succ_state):
        state_addr=self._getExitNodeAddr(succ_state.addr)
        if state_addr:
            state=self.project.factory.blank_state(addr=state_addr,plugins=succ_state.plugins)
            self._simgr.deferred.append(state) 

    
    
    def _getExitNodeAddr(self,addr):
        for en_addr,ex_addr in self._loop_breadedges:
            if addr == en_addr:
                return ex_addr
            
            
    def _isWrFuncCallForHeap(self,blk):
        for addr , props in self._func_heap_wr_sites.items():
            if addr in blk.instruction_addrs:
                return addr
            
        return None
    
    def _isWrFuncCallForStack(self,blk):
        for addr , props in self._func_stack_wr_sites.items():
            if addr in blk.instruction_addrs:
                return addr
            
        return None

    def _setLoopsBound(self,loop):
        addr=[]
        for loopNode in loop.body_nodes:
            addr.append(loopNode.addr)
            
        self._loopsAddrs.append(addr)
        
        
    def _getVarCorrToMallocAddrs(self,m_addr):
        for indx,addr in self._malloc_args.items():
            if addr == m_addr:
                return self._getVariableByName('var_{}'.format(indx))
                
        
    def getNodeByInode(self,inode):
        for node in self._graph.nodes:
            if node.inode == inode:
                return node 
            
            
    def CheckWfreeVuln(self, state, VulnType):
        if not self.NodeStatus :
            self.NodeStatus=[""]*self.PointerNum
            history = state.history.bbl_addrs.hardcopy
            for haddr in history:
                addrStatus = self.WFreeaddrs.get(haddr, [] )
                for pointerStatus in addrStatus:
                    self.NodeStatus[ pointerStatus[0] ] += pointerStatus[1]

        addrStatus = self.WFreeaddrs.get(state.addr, [] )
        for pointerStatus in addrStatus:
            self.NodeStatus[ pointerStatus[0] ] += pointerStatus[1]

        #print( hex(state.addr) , self.NodeStatus)
        pattern = "100+$" if VulnType==2 else "02+$"
        for i in self.NodeStatus :
            if re.search(pattern, i) and self.WFreeaddrs.get(state.addr, None ):
                #print("state = ", state.addr)
                return True
        return False
    
      
    def _collect(self,state,status,VulnType,extra_const=None):
        
        if len(self._graph.nodes) == 0:
            self._root=_VNode(inode=self._inode,addr=state.addr,block=state.addr,constraints=state.solver.constraints,parent_addr=0,satisfiable=status)
            self._inode= self._inode +1
            self._graph.add_node( self._root)
            self._checkForCalle(vex=state.block().vex,target=self._root)
            self._root._has_child=True
            if self._is_static_vul:
                self._root.setVulSusp(True)
                self._is_static_vul=False
            if VulnType > 1 and self.CheckWfreeVuln(state, VulnType) :
                self._root.setVulSusp(True)
                self._vulConstNumb=self._vulConstNumb+1
            if extra_const is not None :
                vulConst,message=extra_const
                self._root.addVulConstraint(vulConst)
                self._root.setVulSusp(True)
                self._root.addVulMessage(message)
                self._vulConstNumb=self._vulConstNumb+1
                if node.inode not in self._generetedVulConst.keys():
                    self._generetedVulConst[node.inode]=[]
                self._generetedVulConst.get(self._root.inode).append(vulConst)
            ##
            stack_values=self.cfg_Analyzer.getSimpleWrINStackFor(self._func.name,block=state.block())
            self._root._setUpStack(stack_values)
            
            wr_st_maps=self._getWrSiteINState(state)
            if len(wr_st_maps) > 0:
                self._checkWrSiteVul(state,wr_st_maps)
        else:

                                
            #if self._isInCallableBoundry(self._func,state.addr) == False:
            if self.project._sim_procedures.get(state.addr, None ):
                return

            parent,parent_add,path=self._findParent(state)
                        
            node=_VNode(inode=self._inode,addr=state.addr,block=state.addr,parent_addr=parent_add,satisfiable=status)
            node.addConstraints(state.solver.constraints,parent)
            ###
            stack_values=self.cfg_Analyzer.getSimpleWrINStackFor(self._func.name,block=state.block())
            node._setUpStack(stack_values,parent._stack)
            wr_st_maps=self._getWrSiteINState(state)
            if len(wr_st_maps) > 0:
                self._checkWrSiteVul(node._stack,state,wr_st_maps)
            
            flag=False
            if len(self._loopsAddrs) > 0:
                if self._isINLoop(state.addr):
                    flag=True
                    isEntry=node.addr in self._loopentries
                    isFirstNode= node.addr in self._loopsFirstNodes
                    if isEntry:
                        self._loopTerm=None
                    if isFirstNode:
                        if len(node.Term)> 0:
                            self._loopTerm=node.Term
                    for p_node in path:
                        if p_node.isEqual(node,isEntryLoop=isEntry):
                            if self._loopTerm:
                                p_node.constraints.extend(self._loopTerm)
                                if isFirstNode:
                                    p_node.Term.extend(self._loopTerm)
                            parent.addBlock(state.addr)
                            parent._correctStack(node._stack)
                            return
                        

            if len(node.Term) == 0 and flag == False:
                parent.addBlock(state.addr)
                parent._correctStack(node._stack)
                if self._is_static_vul:
                    parent.setVulSusp(True)
                    self._is_static_vul=False
                if VulnType > 1 and self.CheckWfreeVuln(state, VulnType) :
                    parent.setVulSusp(True)
                    self._vulConstNumb=self._vulConstNumb+1
                if extra_const is not None :
                    vulConst,message=extra_const
                    parent.setVulSusp(True)
                    parent.addVulConstraint(vulConst)
                    parent.addVulMessage(message)
                    self._vulConstNumb=self._vulConstNumb+1
                    if parent.inode not in self._generetedVulConst.keys():
                        self._generetedVulConst[parent.inode]=[]
                    self._generetedVulConst.get(parent.inode).append(vulConst)
                if state.block().vex.jumpkind == 'Ijk_Ret' or status == False:
                    parent._has_child=False
                else:
                    parent._has_child=True
                parent.setSatisfaiablilyStatus(status)
                del(node)
                return
            else :
                if self._is_static_vul:
                    node.setVulSusp(True)
                    self._is_static_vul=False
                if VulnType > 1 and self.CheckWfreeVuln(state, VulnType) :
                    node.setVulSusp(True)
                    self._vulConstNumb=self._vulConstNumb+1
                if extra_const is not None :
                    vulConst,message=extra_const
                    node.addVulConstraint(vulConst)
                    node.setVulSusp(True)
                    node.addVulMessage(message)
                    self._vulConstNumb=self._vulConstNumb+1
                    if node.inode not in self._generetedVulConst.keys():
                        self._generetedVulConst[node.inode]=[]
                    self._generetedVulConst.get(node.inode).append(vulConst)
                self._checkForCalle(vex=state.block().vex,target=node)
                self._graph.add_edge( parent,node)
                self._inode= self._inode +1
                
            if state.block().vex.jumpkind == 'Ijk_Ret' or status == False:
                node._has_child=False
            else:
                node._has_child=True
            

    def _getWrSiteINState(self,state):
        res={}
        if len(self._heap_wr_sites)>0:
            inst_addrs=state.block().instruction_addrs
            for base_addr,list_wr_addrs in self._heap_wr_sites:
                for wr_addr in list_wr_addrs:
                    if wr_addr in inst_addrs:
                        if base_addr not in res.keys():
                            res[base_addr]=[wr_addr]
                        else:
                            res[base_addr].append(wr_addr)    
        return res
    
    def _checkWrSiteVul(self,current_stack,state,wr_sites):
        if self._isINLoop(state.addr):
            pass
        else:
            for m_addr,wr_list in wr_sites.items():
                for wr_addr in wr_list:
                    self._checkForFixIndexAccess(current_stack,m_addr,wr_addr,state)
                    
                    
    def _checkForFixIndexAccess(self,current_stack,m_addr,wr_addr,state):
        index=self.cfg_Analyzer._isFixedIndexAccess(self._func.name,wr_addr,state.block().vex,list(current_stack.items()))
        malloc_size=self._malloc_boundry[m_addr]
        if index and index >= malloc_size:
            message='There is a Buffer Overflow in block {} with constant write '.format(wr_addr)
            if message not in self._vulReports:
                self._vulReports.append(message)   
        #Extra check for fixed argumnet
        for addr,caller in self.cfg_Analyzer.getCaller(self._func.name):
            fixed_args=self.cfg_Analyzer._getFixArgcOnStack(caller.name,self._func.name)
            new_stack={}
            for addr,value in fixed_args.items():
                if addr not in current_stack.keys():
                    new_stack[addr]=value
            index=self.cfg_Analyzer._isFixedIndexAccess(self._func.name,wr_addr,state.block().vex,list(new_stack.items()))
            malloc_size=self._malloc_boundry[m_addr]
            if index and index >= malloc_size:
                message='There is a Buffer Overflow in block {} with constant write '.format(wr_addr)
                if message not in self._vulReports:
                    self._vulReports.append(message)   
            
                    
    
    def _extractLoopFirstNode(self,loop):
        for en,ex in loop.graph.edges:
            en_addr=en.addr
            try:
                ex_addr=ex.addr
            except:
                print("no addr")
            if en_addr in self._loopentries:
                if (en_addr,ex_addr) not  in self._loop_breadedges:
                    self._loopsFirstNodes.append(ex_addr)
                    return
            
    
    def _isINLoop(self,addr):
        for loopaddrs in self._loopsAddrs:
            if addr in loopaddrs:
                return True
            
        return False
    
    
    def _checkForCalle(self,vex,target):
        if 'Ijk_Call' in vex.constant_jump_targets_and_jumpkinds.values():
            addr=list(vex.constant_jump_targets)[0]
            target._addCallee(addr)   
            
            
    def getStoreDataAtAddress(self,vex,addr):
        visited=False
        target_store=None
        for stmt in vex.statements:
            if stmt.tag == 'Ist_IMark':
                if stmt.addr == addr:
                    visited=True
                else:
                    visited=False
           
            if visited==True :
                if isinstance(stmt,pyvex.IRStmt.Store):
                    target_store=stmt
        
        return target_store.data   
    
    def _isInCallableBoundry(self,func,target_addr):
        for i in func.blocks:
            if target_addr in i.instruction_addrs:
                return True
            
        return False
    
    def getNodeByIndex(self,index):
        return list(self._graph.nodes)[index]
    
    def _correctHistory(self,bbl_addrs):
        hist=[]
        for addr in bbl_addrs:
            if self._isInCallableBoundry(self._func,addr):
                hist.append(addr)
                
        return  hist
                
    def _findParent(self,state):
        hist=self._correctHistory(state.history.bbl_addrs.hardcopy)
        parent=self._root
        path=[parent]
        active=hist.pop(0)
        while len(hist)>0:
            childs=self._successors(parent,depth_limit=1)
            active=hist.pop(0)
            for child in childs:
                if active in child.blocks:
                    parent=child
                    path.append(parent)
                    break
            
        return parent,active,path
    

    def getAllPaths(self):
        """
            get All path of an DiGraph
        """
        roots = (v for v, d in self._graph.in_degree() if d == 0)
        leaves = [v for v, d in self._graph.out_degree() if d == 0]
        all_paths = []
        for root in roots:
            paths = nx.all_simple_paths(self._graph, root, leaves)
            all_paths.extend(paths)
            
        return all_paths
            
    def getVulSupsPaths(self):
        paths=[]
        for path in self.getAllPaths():
            for node in path :
                if node._vul_susp:
                    paths.append(path)
                    break
        return paths
    
    def isInVulSupsPath(self,inode):
        for path in self.getVulSupsPaths():
            for  node  in path :
                if node.inode == inode:
                    return True
        return False

        
    
    def _path_str_(self,path):
        l=[]
        for node in path: 
            l.append(str(node.inode))
        print('  \u2192 '.join(l))
        del(l)
    
    def _successors(self,parent,depth_limit):
        return list(nx.bfs_successors(self._graph,parent,depth_limit=depth_limit))[0][1]
    
    def _parent(self,target_node):
        parent=nx.predecessor(self._graph,source=self._root,target=target_node)
        if len(parent) > 0:
            return parent[0]
        else:
            return target_node
    
    
    def setUpHeapVulConstraints(self,curr_wfCall_vb,curr_wfCall,rhs,hist_call,buff_type,iswchar=False,):
        #print(self._func_heap_wr_sites.keys())
        if curr_wfCall in self._func_heap_wr_sites.keys():
            props=self._func_heap_wr_sites[curr_wfCall]
            #print(' *** props  : ' ,props)
            if props[0] == 'strcpy':
                return self._getVulConstraintsForStrcpy(curr_wfCall_vb,props,rhs,hist_call,buff_type)
            if props[0] == 'strcat':
                return self._getVulConstraintsForStrcat(curr_wfCall_vb,props,rhs,hist_call,buff_type)
            if props[0] == 'strncpy':
                return self._getVulConstraintsForStrncpy(curr_wfCall_vb,props,rhs,hist_call,buff_type)            
            if props[0] == 'strncat':
                return self._getVulConstraintsForStrncat(curr_wfCall_vb,props,rhs,hist_call,buff_type)
            if props[0] == 'memcpy' or props[0] == 'memmove':
                return self._getVulConstraintsForMemcpy(curr_wfCall_vb,props,rhs,hist_call,buff_type,wchar=iswchar)
            if props[0] == 'memset':
                return self._getVulConstraintsForMemset(curr_wfCall_vb,props,rhs,hist_call,buff_type,wchar=iswchar)
            if props[0] == 'sprintf':
                return self._getVulConstraintsForSprintf(curr_wfCall_vb,props,rhs,hist_call,buff_type)
        
    def setUpStackVulConstraints(self,curr_wfCall_vb,curr_wfCall,rhs,hist_call,buff_type,iswchar=False):
        #print(self._func_stack_wr_sites.keys())
        if curr_wfCall in self._func_stack_wr_sites.keys():
            props=self._func_stack_wr_sites[curr_wfCall]
            #print(' *** props  : ' ,props)
            if props[0] == 'strcpy':
                return self._getVulConstraintsForStrcpy(curr_wfCall_vb,props,rhs,hist_call,buff_type)
            if props[0] == 'strcat':
                return self._getVulConstraintsForStrcat(curr_wfCall_vb,props,rhs,hist_call,buff_type)
            if props[0] == 'strncpy':
                return self._getVulConstraintsForStrncpy(curr_wfCall_vb,props,rhs,hist_call,buff_type)     
            if props[0] == 'strncat':
                return self._getVulConstraintsForStrncat(curr_wfCall_vb,props,rhs,hist_call,buff_type)  
            if props[0] == 'memcpy' or props[0] == 'memmove':
                return self._getVulConstraintsForMemcpy(curr_wfCall_vb,props,rhs,hist_call,buff_type,wchar=iswchar)
            if props[0] == 'memset':
                return self._getVulConstraintsForMemset(curr_wfCall_vb,props,rhs,hist_call,buff_type,wchar=iswchar)
            if props[0] == 'sprintf':
                return self._getVulConstraintsForSprintf(curr_wfCall_vb,props,rhs,hist_call,buff_type)    
        

    def _getVulConstraintsForSprintf(self,vex,props,rhs,history_blocks,buff_type):
        func_name,out_str=rhs
        if isinstance(out_str,str):
            dst_size=self._getSRCorDSTsize('sprintf',vex,props,'dst',history_blocks,buff_type)
            if dst_size:
                if len(out_str) > dst_size:
                    self._is_static_vul=True
                    self._vulReports.append('There is a Buffer Overflow in block {} with target function sprintf '.format(vex.addr))
                

    def _getVulConstraintsForMemset(self,vex,props,rhs,history_blocks,buff_type,wchar=False):
        func_name,num=rhs
        dst_size=self._getSRCorDSTsize('memset',vex,props,'dst',history_blocks,buff_type,iswhar=wchar)
        if dst_size:
            message='There is a Buffer Overflow in block {} with target function memset '.format(vex.addr)
            if isinstance(num,int):
                if num > dst_size:
                    self._is_static_vul=True
                    self._vulReports.append(message)
            else:
                return (num > dst_size,message)
                
                
            
    def _getVulConstraintsForStrncpy(self,vex,props,rhs,history_blocks,buff_type):
        func_name,limit=rhs
        message='There is a Buffer Overflow in block {0} with target function {1}'.format(vex.addr,props[0])
        if isinstance(limit,int):
            dst_size=self._getSRCorDSTsize(func_name,vex,props,'dst',history_blocks,buff_type)
            #print("dst_size:", dst_size)
            if dst_size:
                if limit > dst_size:
                    self._is_static_vul=True
                    self._vulReports.append(message)   
        else:
            dst_size=self._getSRCorDSTsize(func_name,vex,props,'dst',history_blocks,buff_type)
            src_size=self._getSRCorDSTsize(func_name,vex,props,'src',history_blocks,buff_type)
            #print("dst_size:", dst_size)
            #print("src_size:", src_size)
            if dst_size and src_size:
                const=[limit <= src_size ,limit > dst_size]
                return (claripy.And(*const),message)

    def _getVulConstraintsForStrncat(self,vex,props,rhs,history_blocks,buff_type):
        func_name,limit=rhs
        message='There is a Buffer Overflow in block {0} with target function {1}'.format(vex.addr,props[0])
        if isinstance(limit,int):
            dst_size=self._getSRCorDSTsize(func_name,vex,props,'dst',history_blocks,buff_type)
            #print("dst_size:", dst_size)
            if dst_size:
                if limit > dst_size:
                    self._is_static_vul=True
                    self._vulReports.append(message)   
        else:
            dst_size=self._getSRCorDSTsize(func_name,vex,props,'dst',history_blocks,buff_type)
            src_size=self._getSRCorDSTsize(func_name,vex,props,'src',history_blocks,buff_type)
            #print("dst_size:", dst_size)
            #print("src_size:", src_size)
            if dst_size and src_size:
                const=[limit > dst_size - dst_len ,limit <= dst_size]
                return (claripy.And(*const),message)   
                 
        
    def _getVulConstraintsForMemcpy(self,vex,props,rhs,history_blocks,buff_type,wchar=False):       
        func_name,limit=rhs
        message='There is a Buffer Overflow in block {0} with target function {1}'.format(vex.addr,props[0])
        if isinstance(limit,int):
            dst_size=self._getSRCorDSTsize(func_name,vex,props,'dst',history_blocks,buff_type,iswhar=wchar)
            #print("dst_size:", dst_size)
            if dst_size:
                if limit > dst_size:
                    self._is_static_vul=True
                    self._vulReports.append(message)   
        else:
            dst_size=self._getSRCorDSTsize(func_name,vex,props,'dst',history_blocks,buff_type,iswhar=wchar)
            src_size=self._getSRCorDSTsize(func_name,vex,props,'src',history_blocks,buff_type,iswhar=wchar)
            #print("dst_size:", dst_size)
            #print("src_size:", src_size)
            if dst_size and src_size:
                const=[limit <= src_size ,limit > dst_size]
                return (claripy.And(*const),message)
                
            
    def _getVulConstraintsForStrcpy(self,vex,props,rhs,history_blocks,buff_type):
        message='There is a Buffer Overflow in block {} with target function strcpy'.format(vex.addr)
        if isinstance(rhs,str):
            dst_size=self._getSRCorDSTsize('strcpy',vex,props,'dst',history_blocks,buff_type)
            #print("dst_size:", dst_size)
            #print("src_size:", src_size)
            if dst_size:
                len_rhs=len(rhs)
                if len_rhs >=  dst_size:
                    self._is_static_vul=True
                    self._vulReports.append(message)
        else:
            src_size=self._getSRCorDSTsize('strcpy',vex,props,'src',history_blocks,buff_type)
            dst_size=self._getSRCorDSTsize('strcpy',vex,props,'dst',history_blocks,buff_type)
            #print("dst_size:", dst_size)
            #print("src_size:", src_size)
            const=[]
            if src_size and dst_size:
                if src_size < dst_size:
                    return None
                
                const.append(claripy.UGT(rhs ,dst_size)) 
                #const.append(claripy.ULE(rhs,src_size))
                return (claripy.And(*const),message)

            elif dst_size:
                const.append(claripy.UGT(rhs ,dst_size))
                #const.append(claripy.ULE(rhs,src_size))
                return (claripy.And(*const),message)


    def _getVulConstraintsForStrcat(self,vex,props,rhs,history_blocks,buff_type):
        func_name,dst_len,src_len=rhs
        message='There is a Buffer Overflow in block {} with target function strcat'.format(vex.addr)
        if isinstance(src_len,int):
            dst_size=self._getSRCorDSTsize('strcat',vex,props,'dst',history_blocks,buff_type)
            if dst_size:
                if src_len > dst_size :
                    self._is_static_vul=True
                    self._vulReports.append(message)
                else:
                    const=dst_size - dst_len <  src_len
                    if 'BoolV' == const.op and const.is_false():
                        return

                    return (const,message)
        else:
            src_size=self._getSRCorDSTsize('strcat',vex,props,'src',history_blocks,buff_type)
            dst_size=self._getSRCorDSTsize('strcat',vex,props,'dst',history_blocks,buff_type)
            #print("dst_size:", dst_size)
            #print("src_size:", src_size)
            #print("dest_len:", dst_len)
            if src_size and dst_size:
                const=[dst_size - dst_len < src_len , src_len < src_size]
                #print('const ' , const)
                return (claripy.And(*const),message)
            elif dst_size:
                const=[src_len > dst_size]
                #print('const 2 : ',const)
                return (claripy.And(*const),message)
        
        
    def _getSRCorDSTsize(self,func_name,vex,props,arg_type,history_blocks,buff_type,iswhar=False):
        res_addr=None
        tmp_props_addr=[]
        is_inFunc=True
        for addr,tp in props[1:]:
            if tp == arg_type:
                try:
                    if self._func.name !=self.cfg_Analyzer.resolveAddrByFunction(addr).name :
                        is_inFunc=False
                except:
                    print(' *** Stack Buffer ***')
                tmp_props_addr.append(addr)


        if len(tmp_props_addr) == 1:
            res_addr=tmp_props_addr.pop()
        elif len(tmp_props_addr) > 1 :
            if is_inFunc:
                res_addr=self._getCurrectADdrBasedInHistory(history_blocks,tmp_props_addr)
            else:
                r = tmp_props_addr.pop()
                if r in self._malloc_boundry.keys():
                    buffer_size=self._malloc_boundry[r]
                else:
                    buffer_size=self._stack_boundry[str(self._func.name) + '-' + str(r)]
                    
                for addr in tmp_props_addr:
                    if addr in self._malloc_boundry.keys():
                        malloc_addr=self._malloc_boundry[addr]
                    else:
                        malloc_addr=self._stack_boundry[str(self._func.name) + '-' + str(addr)]
                        
                    if arg_type == 'src':
                        if malloc_addr >= buffer_size:
                            res_addr=addr
                            buffer_size=malloc_addr
                    else:
                        if malloc_addr <= buffer_size:
                            res_addr=addr
                            buffer_size=malloc_addr
                
            
        if res_addr is None :
            if arg_type == 'src':
                return self._getArgvSizeForSRC(self._func.name,func_name,vex)
            else:
                return None

            
       # if arg_type == 'src':
       #     return self._getArgvSizeForSRC(self._func.name,func_name,vex)
       # elif res_addr is None:
       #     return None

        arg_index=1 if arg_type=='src' else 0

        if res_addr in self._malloc_boundry.keys():
            res_size=self._malloc_boundry[res_addr]
        else:
            res_size=self._stack_boundry[str(self._func.name) + '-' + str(res_addr)]
        
        if buff_type == 'heap':    
            arg_indexing=self.cfg_Analyzer._trackInputOfFuncionCall(vex,arg_index,self.cfg_Analyzer.getFuncAddress(func_name),just_index=True)
            if arg_indexing is not None:
                res_size=res_size - arg_indexing[1].con.value

        if iswhar:
            res_size=int(res_size/4)
            
        return res_size
    
    def _getArgvSizeForSRC(self,func_name,target_func,vex):
        target_funAddr=self.cfg_Analyzer.getFuncAddress(target_func)
        argc=self.cfg_Analyzer.getArgsCC(vex,target_funAddr)
        maps=self._getMapForArgv(func_name)
        index=None
        map_index={}
        for chainCnt,props in maps.items():
            if func_name in props.keys():
                for prp in props[func_name]:
                    reg,addr,opr=prp
                    argc_reg,argc_addr,argc_opr=argc[1]
                    if addr.con.value == argc_addr.con.value:
                        map_index[chainCnt]=props[func_name].index(prp)
        if len(map_index) > 0:
            chains=list(set(self.cfg_Analyzer.getCallChain(func_name)))
            for chainIndx,index in map_index.items():
                target_chain=chains[chainIndx]
                items=target_chain.split('-')
                target_regname=maps[chainIndx].get(func_name)[index][0]
                argcArgsTrack=self.cfg_Analyzer.checkForArgvAsArgument(items[1])
                if len(argcArgsTrack)==1:
                    for addr,argv_props in argcArgsTrack.items():
                        for argv_idx,argv_reg in argv_props:
                            if argv_reg == target_regname:
                                return self._argv[argv_idx]
                else:
                    raise Exception("Not Support")
                            
            
                
    
    def _getMapForArgv(self,func_name):
        chains=set(self.cfg_Analyzer.getCallChain(func_name))
        maps={}
        count=0
        for chain in chains:
            items=chain.split('-')
            if len(items) < 2: 
                count=count+1
                continue
            caller=items.pop(0)
            callee=items.pop(0)
            maps[count]={}
            argv=self.cfg_Analyzer.getArgvAddrsOnStack()
            if argv is None: 
                count=count+1
                continue
            maps[count][caller]=[argv]
            while True: 
                for addr ,props in self.cfg_Analyzer._mapRegccInCalleeAndCaller(caller,callee,maps[count].get(caller)):
                    if len(props) > 0 : 
                        maps[count][callee]=props
                if len(items) ==0 : break
                caller=callee
                callee=items.pop(0)
            count=count+1
        return maps
        
        
        
        
    def _getCurrectADdrBasedInHistory(self,history_blocks,target_addrs):
        tmp_res={}
        index=0
        for blck_addr in history_blocks:
            block=self.cfg_Analyzer.getBlockRelatedToAddr(blck_addr)
            for addr in target_addrs:
                if addr in block.instruction_addrs:
                    tmp_res[addr]=index
            index=index+1
        m_index=-1
        m_addr=-1
        while len(tmp_res)>0:
            addr,index=tmp_res.popitem()
            if index > m_index:
                m_index=index
                m_addr=addr
        return addr
    
        
        
        
        

