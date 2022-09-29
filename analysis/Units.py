#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jul 13 16:59:10 2020

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""
import networkx as nx
import pandas as pd

class Units:
    
    def __init__(self,valAnalysis):
        self._analysis=valAnalysis
        self.malloc_map={}
        self.argv_map={}
        self.free_map={}
       #self._setUpArgvMap()
        self._setUpFreeMap()


    def _setUpFreeMap(self):
        for addr, func in set(self._analysis.getCaller('free')):
            func_callblocks = self._analysis.getBlockOFFuctionCall('free',func.name)
            if func_callblocks is None:
                continue 

            src_argc = self._analysis.project.factory.cc().ARG_REGS[0]
            for callblock in func_callblocks:
                free_addr = callblock.instruction_addrs[-1]
                for argc in self._analysis.getArgsCC(callblock.vex, self._analysis.getFuncAddress('free')):
                    if argc[0] == src_argc:
                        self.free_map[free_addr] = (func.name, argc)
        

    def getUnitForStackBufferOverflow(self):
        chains = []
        dgrFunctions=['strcpy','strncpy','strncat','strcat','memcpy','memset','memmove','sprintf']
        for dgrFunc in dgrFunctions:
            chain_list = list(set(self._analysis.getCallChain(dgrFunc)))
            if chain_list[0] not in dgrFunctions:
                chains.extend(chain_list)

        chain_map, func_args_map = self._getChainMap(chains)
        
        tmp_res = []
        relative_address_list =[]
        for item in self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctions()):
            if self._analysis.isReachableFromMain(item[1].name):
                result, relative_address = self._checkForDengrouseFunction_Stack(item[1].name)
                tmp_res.extend(result)
                relative_address_list.extend(relative_address)

        stack_buffers = []
        relative_addr = []
        for item in tmp_res:
            dgrFunc_caller, src, name, addr, arg_type = item
            src_found = False
            src_offset = src[1]
            caller_args_num, caller_args = func_args_map[dgrFunc_caller]

            for arg in caller_args:
                if arg[1] == src_offset:
                    src_found = True; break

            if  src_found == True:
                for chain_key in chain_map.keys():
                    caller, callee = chain_key.split('-')
                    if callee == dgrFunc_caller:
                        passed_args = chain_map[chain_key]
                        for argc in passed_args:
                            for arg in argc:
                                if arg[2] == str(src_offset):
                                    if 'stack' in arg[0] and arg_type != 'copy_len':
                                        stack_buffers.append((dgrFunc_caller, src, (name, addr, arg_type)))
                                        dgrFunc_caller2, src2, name2, addr2, arg_type2 = relative_address_list[tmp_res.index(item)]
                                        relative_addr.append((dgrFunc_caller2, src2, (name2, addr2, arg_type2)))            
            if  src_found == False:     
                for malloc_addr, buffers in self.malloc_map.items():
                    buffer_func = buffers[0][0]
                    malloc_src_offset = buffers[0][1][1]
                    if dgrFunc_caller == buffer_func and src_offset == malloc_src_offset:
                        src_found = True; break

            if src_found == False and arg_type != 'copy_len':
                stack_buffers.append((dgrFunc_caller, src, (name, addr, arg_type)))
                dgrFunc_caller2, src2, name2, addr2, arg_type2 = relative_address_list[tmp_res.index(item)]
                relative_addr.append((dgrFunc_caller2, src2, (name2, addr2, arg_type2)))  

        #print(stack_buffers, relative_addr)
        return stack_buffers, relative_addr
        
        
    def getUnitForHeapBufferOverFlow(self):
        result=[]
        for addr , func in self._analysis.getCaller('malloc'):
            begin=func.startpoint.addr
            end=self._analysis.getEndPoint(func.name)
            
            malloc_pro=dict()
            for i in self._analysis.getRetStoreLocOnStackOfFunction('malloc',func.name):
                for addr,value in i.items():
                    if value is None: continue
                    malloc_pro[addr]=value
                        
            for addr,argcc in malloc_pro.items():
                if addr not in self.malloc_map.keys():
                    self.malloc_map[addr]=[(func.name,argcc)]
                    self._applyCopiesPositions(addr,func.name,argcc)
                        
                
            #TODO : check free is called in callee function or in functions called
            
            funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(func.name,begin,end))
            for f_addr,f_name in funcs:
                for callblock in self._analysis.getBlockOFFuctionCall(f_name,func.name):
                    new_malloc=self._refinedMallocFromMaps(func.name)
                    refined_malloc=self._getRefinedMallocProForFunc(callblock,func.name,new_malloc)
                    self._setUpMallocMap(func.name,f_name,refined_malloc)

                            
             
            #here must be do it 
            for m_addr,props in malloc_pro.items():
                end_p=self._analysis.isMallocReterned(props[1].con.value,func)
                if end_p:
                    for func_Addr,c_func in self._analysis.getCaller(func.name):
                        caller_malloc_pro={}
                        value=tuple(self._analysis.getRetStoreLocOnStackOfFunction(func.name,c_func.name)[0].values())
                        if value[0]:
                            caller_malloc_pro[m_addr]=[value[0]]
                            self.malloc_map[m_addr].append((c_func.name,value[0]))
                            self._applyCopiesPositions(m_addr,c_func.name,value[0])

                            begin=c_func.startpoint.addr
                            end=self._analysis.getEndPoint(c_func.name)
                            funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(c_func.name,begin,end))
                            for f_addr,f_name in funcs:
                                for callblock in self._analysis.getBlockOFFuctionCall(f_name,c_func.name):
                                    refined_malloc=self._getRefinedMallocProForFunc(callblock,c_func.name,caller_malloc_pro)
                                    self._setUpMallocMap(c_func.name,f_name,refined_malloc)
 
                                 
        for item in self._checkForWrits():
            if item not in result:    
                result.append(item) 
              
        return result
    

    def FindUnit(self, nodeName, goal, G):
        for node in list(G.successors(nodeName)):
            if G.nodes[node]['num'] == goal :
                return self.FindUnit(node, goal, G)
        else :
            return nodeName

    def MyGetCallChain(self, funcName, funcs, G):
        if funcName not in funcs:
            G.add_node(funcName)
            funcs.add(funcName)
            func=self._analysis.resolveAddrByFunction(self._analysis.getFuncAddress(funcName))
            begin=func.startpoint.addr
            end=self._analysis.getEndPoint(func.name)

            subFunc = self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(func.name,begin,end))

            for addr, f in subFunc:
                G.add_edge(funcName, f)
                self.MyGetCallChain(f, funcs, G)


    def getUnitForDoubleFree(self, ptrNum, resF):
        
        res =  [ [] for i in range(ptrNum)]
        for addr, status in resF.items():
            res[status[0][0]].append( addr )
        
        result=[]
        G = nx.DiGraph()
        funcs = set()
        self.MyGetCallChain('main', funcs, G)

        for item in res :
            for node in G.nodes:
                G.nodes[node]['num'] = 0

            for addr in item :
                fname = self._analysis.resolveAddrByFunction(addr).name
                G.nodes[fname]['num'] =  G.nodes[fname]['num'] +1
                predecessors = list(G.predecessors(fname))
                i=0
                while i < len(predecessors) :
                    p = predecessors[i]
                    G.nodes[p]['num'] =  G.nodes[p]['num'] +1
                    if list(G.predecessors(p)) :
                        predecessors.append(*list(G.predecessors(p)))
                    i+=1
            unit_function_name = self.FindUnit('main', G.nodes['main']['num'], G)
            result.append(unit_function_name)

        return result
 
    
    def _applyCopiesPositions(self,addr,func_name,props):
        tmp_res={}
        for new_props in self._analysis.getAllCopiesSites(func_name,props[1].con.value):
            if addr not in tmp_res.keys():
                tmp_res[addr]=[]
            tmp_res[addr].append((func_name,new_props))

        for addr,wr_list in tmp_res.items():
            for item in wr_list:
                self.malloc_map[addr].append(item)

    def _getArgsType(self, chain_map, func_name, src_offset):
        result = []
        for chain_key in chain_map.keys():
            caller, callee = chain_key.split('-')
            if callee == func_name:
                passed_args = chain_map[chain_key]
                for argc in passed_args:
                    for arg in argc:
                        if arg[2] == str(src_offset):

                            if len(arg[0]) > 1:
                                result.extend(arg[0])

                            elif len(arg[0]) == 1:
                                if arg[0][0] == 'stack' or arg[0][0] == 'heap':
                                    result.extend(arg[0])

                                elif arg[0][0] == 'args':
                                    if caller == 'main':
                                        result.extend(arg[0])
                                    else:
                                        result.extend(self._getArgsType(chain_map, caller, arg[1]))
        return result


    def _getChainMap(self, chains):
        chain_map = {}
        func_args_map = {}
        function_calls = []
        chains = [chain.split('-') for chain in chains]
        main_vex = self._analysis.getBlockOfFunctionAt('main',0).vex
        main_args_num, main_args_offset = self._analysis.getArgsOFFunction(main_vex)
        func_args_map['main'] = (main_args_num, main_args_offset)

        for chain in chains:
            while len(chain) > 2:
                current_func = chain[0]
                next_func = chain[1]
                #print(current_func, ' ---> ', next_func)
                chain_key = current_func + '-' + next_func 
                if chain_key in chain_map.keys():
                    chain.remove(current_func)
                    continue

                if next_func in func_args_map.keys():
                    next_agrs_num, next_args_offset = func_args_map[next_func]

                else:    
                    next_vex = self._analysis.getBlockOfFunctionAt(next_func,0).vex
                    next_agrs_num, next_args_offset = self._analysis.getArgsOFFunction(next_vex)
                    func_args_map[next_func] = (next_agrs_num, next_args_offset)

                regs = [next_args_offset[i][0] for i in range(len(next_args_offset))]
                func_callblock = self._analysis.getBlockOFFuctionCall(next_func,current_func)

                for callblock in func_callblock:
                    func_call = []
                    passed_args = self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(next_func))
                    for argc in passed_args:
                        if argc[0] in regs: 
                            src_type = None
                            for res in next_args_offset:
                                if res[0] == argc[0]:
                                    next_func_offset = res[1]

                            # if there is a malloc in cutrent function
                            for malloc_addr, buffers in self.malloc_map.items():
                                buffer_func = buffers[0][0]
                                malloc_src_offset = buffers[0][1][1]
                                if buffer_func == current_func and argc[1] == malloc_src_offset:
                                    src_type = ['heap']

                            # if args which is passed is comming from agrs of current function
                            if src_type == None:
                                #print(current_func)
                                if current_func in func_args_map.keys():
                                    current_agrs_num, current_args_offset = func_args_map[current_func]

                                else:    
                                    current_vex = self._analysis.getBlockOfFunctionAt(current_func,0).vex
                                    current_agrs_num, current_args_offset = self._analysis.getArgsOFFunction(current_vex)
                                    func_args_map[current_func] = (current_agrs_num, current_args_offset)

                                for res_c in current_args_offset:
                                    if res_c[1] == argc[1]:
                                        if current_func == 'main':
                                            src_type = ['args']
                                        else:
                                            src_type = self._getArgsType(chain_map, current_func, argc[1])
                                            
                            # if args which is passed is not comming from an malloc and args so it refers to stack
                            if src_type == None:
                                src_type = ['stack']

                            func_call.append((src_type, hex(argc[1].con.value), hex(next_func_offset.con.value)))

                    if func_call not in function_calls:
                        function_calls.append(func_call)

                chain_map[chain_key] = function_calls
                chain.remove(current_func) 
                function_calls = []

        return chain_map, func_args_map
                

    def _setUpMallocMap(self,caller,callee_name,malloc_pro):
        #getting malloc addresses
        if len(malloc_pro) ==0 : 
            return malloc_pro


        call_chains=self._getCallChain(callee_name)
        for addr,argc in self.searchInMaps(caller):
                res=self._analysis._mapRegccInCalleeAndCaller(caller,callee_name,[argc])[0][1]
                if len(res)>0 :
                    if self._isINMap(addr,callee_name,res[0]) == False:
                        self.malloc_map[addr].append((callee_name,res[0]))
                        self._applyCopiesPositions(addr,callee_name,res[0])



        for chain in call_chains:
            chain_caller,chain_callee=chain
            for addr,argc in self.searchInMaps(chain_caller):
                res=self._analysis._mapRegccInCalleeAndCaller(chain_caller,chain_callee,[argc])
                if len(res)>0:
                    res=res[0][1]
                    if len(res)>0 :
                        if self._isINMap(addr,chain_callee,res[0]) == False:
                            self.malloc_map[addr].append((chain_callee,res[0]))
                            self._applyCopiesPositions(addr,chain_callee,res[0])
    

    def _getRefinedMallocProForFunc(self,callblock,caller,old_malloc):
        new_malloc={}
        for addr , values in old_malloc.items():
            for value in values:
                if self._isValidAddress(callblock,caller,value):
                    new_malloc[addr]=value
        return new_malloc
    
    def _refinedMallocFromMaps(self,target_name):
        new_malloc={}
        for addr,argc in self.searchInMaps(target_name):
            if addr not in new_malloc.keys():
                new_malloc[addr]=[]
            new_malloc[addr].append(argc)
        return new_malloc    
      
    
    def _checkForWrits(self):
        unit_list=list()
        for addr,items in self.malloc_map.items():
            for func_name,argcc in items:
                if argcc[0] == 'static':
                    res=self._checkWriteForStatic(addr,func_name,argcc)
                    if len(res)>0:
                        unit_list.extend(res)
                else:
                    res=self._analysis.trackWriteIntoARGCCINCallee(func_name,argcc)
                    tmp_res=self._checkForDengrouseFunction(func_name,argcc)
                    for item in tmp_res:
                        if len(item)>0:
                            unit_list.append((addr,func_name,item))
                    if len(res)>0:
                        unit_list.append((addr,func_name,res))
        return unit_list
           

    def _checkWriteForStatic(self,m_addr,func_name,argcc):
        tp,mem_addr,begin=argcc
        unit_list=[]
        wr_res=self._analysis.trackWritesIntoStaticVars(func_name,mem_addr)
        if len(wr_res) > 0:
            unit_list.append((m_addr,func_name,wr_res))
        
        tmp_res=self._checkForDengrouseFunction(func_name,argcc)
        for item in tmp_res:
            if len(item)>0:
                unit_list.append((m_addr,func_name,item))
                
        end=self._analysis.getEndPoint(func_name)
        funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(func_name,begin,end))
        
        for begin_addr , func in self._analysis.getCaller(func_name):
            end_addr=end=self._analysis.getEndPoint(func.name)
            funcs.extend(self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(func.name,begin_addr,end_addr)))
            
        
        for f_addr,f_name in funcs:
            for new_props in self._analysis.getAllCopiesSites(f_name,argcc[1]):
                    self.malloc_map[m_addr].append((f_name,new_props))    
        
        for f_addr,f_name in funcs:
            wr_res=self._analysis.trackWritesIntoStaticVars(f_name,mem_addr)
            if len(wr_res) > 0:
                unit_list.append((m_addr,f_name,wr_res))
            
            tmp_res=self._checkForDengrouseFunction(f_name,argcc)
            for item in tmp_res:
                if len(item)>0:
                    unit_list.append((m_addr,func_name,item))   
                
            
        return unit_list
    

    
    
    def  _isINMap(self,addr,callee_name,argc):
        target=self.malloc_map[addr]
        for func_name,t_argc in target:
            if func_name == callee_name:
                if argc[0] == t_argc[0] and argc[1].con.value == t_argc[1].con.value and argc[2] == t_argc[2]:
                        return True
        return False
            
            
            
    def _checkForDengrouseFunction(self,caller,argcaller):
        dgrFunctions=['strcpy','strncpy','strncat','strcat','memcpy','memset','memmove','sprintf']
        result=[]
        tmp_res=self._checkForStrFuncs('strcpy',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)

        tmp_res=self._checkForMEMStrFuncs('strncpy',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        tmp_res=self._checkForStrFuncs('strcat',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)

        tmp_res=self._checkForMEMStrFuncs('strncat',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
        
        tmp_res=self._checkForMEMStrFuncs('memcpy',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        tmp_res=self._checkForMEMStrFuncs('memmove',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
        
        tmp_res=self._checkForMEMStrFuncs('memset',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        tmp_res=self._checkForSprintf('sprintf',caller,argcaller)
        if tmp_res is not None:
            result.extend(tmp_res)
            
        return result
        


    def _checkForDengrouseFunction_Stack(self,caller):
        dgrFunctions=['strcpy','strncpy','strcat','strncat','memcpy','memset','memmove','sprintf']
        result=[]
        relative_addr_list=[]
        tmp_res, relative_addr=self._checkForStrFuncs_Stack('strcpy',caller)
        if tmp_res is not None:
            result.extend(tmp_res)
            relative_addr_list.extend(relative_addr)

        tmp_res, relative_addr=self._checkForMEMStrFuncs_Stack('strncpy',caller)
        if tmp_res is not None:
            result.extend(tmp_res)
            relative_addr_list.extend(relative_addr)
            
        tmp_res, relative_addr=self._checkForStrFuncs_Stack('strcat',caller)
        if tmp_res is not None:
            result.extend(tmp_res)
            relative_addr_list.extend(relative_addr)

        tmp_res, relative_addr=self._checkForMEMStrFuncs_Stack('strncat',caller)
        if tmp_res is not None:
            result.extend(tmp_res)
            relative_addr_list.extend(relative_addr)
        
        tmp_res, relative_addr=self._checkForMEMStrFuncs_Stack('memcpy',caller)
        if tmp_res is not None:
            result.extend(tmp_res)
            relative_addr_list.extend(relative_addr)
            
        tmp_res, relative_addr=self._checkForMEMStrFuncs_Stack('memmove',caller)
        if tmp_res is not None:
            result.extend(tmp_res)
            relative_addr_list.extend(relative_addr)
        
        tmp_res, relative_addr=self._checkForMEMStrFuncs_Stack('memset',caller)
        if tmp_res is not None:
            result.extend(tmp_res)
            relative_addr_list.extend(relative_addr)
            
        tmp_res, relative_addr=self._checkForSprintf_Stack('sprintf',caller)
        if tmp_res is not None:
            result.extend(tmp_res)
            relative_addr_list.extend(relative_addr)
            
        return result, relative_addr_list   


    def _checkForSprintf_Stack(self,func_name,caller):
        func_callblock=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblock is None:
            return 
        
        result=[]
        relative_addr=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        for callblock in func_callblock:
            for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                argc_copy = argc
                pointer_reference = self._analysis._is_pointer(callblock, caller, argc[1].con.value)
                if pointer_reference != False:
                    new_argc = (argc[0], pointer_reference, argc[2])
                    argc = new_argc
                if argc[0] == dst_argc:
                    result.append((caller, argc, func_name,callblock.instruction_addrs[-1],'dst') )
                    relative_addr.append((caller, argc_copy, func_name,callblock.instruction_addrs[-1],'dst'))
                    
        return result, relative_addr
    

    def _checkForMEMStrFuncs_Stack(self,func_name,caller):
        func_callblock=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblock is None:
            return 
        
        result=[]
        relative_addr=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        src_argc=self._analysis.project.factory.cc().ARG_REGS[1]
        len_argc=self._analysis.project.factory.cc().ARG_REGS[2]
        for callblock in func_callblock:
            for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                argc_copy = argc
                pointer_reference = self._analysis._is_pointer(callblock, caller, argc[1].con.value)
                #print("pointer_reference = ", pointer_reference, argc_copy[1])
                if pointer_reference != False:
                    new_argc = (argc[0], pointer_reference, argc[2])
                    argc = new_argc
                if argc[0] == dst_argc:
                    result.append((caller, argc, func_name,callblock.instruction_addrs[-1],'dst') )
                    relative_addr.append((caller, argc_copy, func_name,callblock.instruction_addrs[-1],'dst'))
                if argc[0] == src_argc:
                    result.append((caller, argc, func_name,callblock.instruction_addrs[-1],'src') )
                    relative_addr.append((caller, argc_copy, func_name,callblock.instruction_addrs[-1],'src'))
                if argc[0] == len_argc:
                    result.append((caller, argc, func_name,callblock.instruction_addrs[-1],'copy_len') )
                    relative_addr.append((caller, argc_copy, func_name,callblock.instruction_addrs[-1],'copy_len'))
                    
        return result, relative_addr
    
    def _checkForStrFuncs_Stack(self,func_name,caller):
        func_callblocks=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblocks is None:
            return 
        
        result=[]
        relative_addr=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        src_argc=self._analysis.project.factory.cc().ARG_REGS[1]
        for callblock in func_callblocks:
            for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                argc_copy = argc
                pointer_reference = self._analysis._is_pointer(callblock, caller, argc[1].con.value)
                if pointer_reference != False:
                    new_argc = (argc[0], pointer_reference, argc[2])
                    argc = new_argc
                if argc[0] == dst_argc:
                    result.append((caller, argc, func_name,callblock.instruction_addrs[-1],'dst') )
                    relative_addr.append((caller, argc_copy, func_name,callblock.instruction_addrs[-1],'dst'))
                if argc[0] == src_argc:
                    result.append((caller, argc, func_name,callblock.instruction_addrs[-1],'src') )
                    relative_addr.append((caller, argc_copy, func_name,callblock.instruction_addrs[-1],'src'))

        return result, relative_addr    
    
    
    def _trackArgvInFunctions(self,caller,callee_name):

        if caller == 'main':
            self.argv_map[caller] = self._analysis.getArgvAddrsOnStack()
            
        call_chains = self._getCallChain(callee_name)
        argc = self.argv_map[caller]
        res = self._analysis._mapRegccInCalleeAndCaller(caller,callee_name,[argc])#[0][1]
        
        for r in res:
            if len(r[1]) > 0:
                self.argv_map[callee_name] = r[1][0]
            
        for chain in call_chains:
            chain_caller,chain_callee = chain
            if chain_caller == callee_name:
                argc = self.argv_map[chain_caller]
                res = self._analysis._mapRegccInCalleeAndCaller(chain_caller,chain_callee,[argc])

                for r in res:
                    if len(r[1]) > 0:
                        self.argv_map[chain_callee] = r[1][0]
    
    
    def _setUpArgvMap(self):
        func = self._analysis.resolveAddrByFunction(self._analysis.getFuncAddress('main'))
        begin = func.startpoint.addr
        end = self._analysis.getEndPoint(func.name)

        funcs = self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(func.name,begin,end))
        #remove duplicates
        funcs = list(dict.fromkeys(funcs))
        for f_addr,f_name in funcs:
            for callblock in self._analysis.getBlockOFFuctionCall(f_name,func.name):
                self._trackArgvInFunctions(func.name,f_name)    
    

    
    def _checkForSprintf(self,func_name,caller,argcaller):
        func_callblock=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblock is None:
            return 
        
        result=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        
        if argcaller[0] == 'static':
            for callblock in func_callblock:
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,dst_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'dst') )
        else:
            for callblock in func_callblock:
                for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == dst_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                    
        return result

    
    def _checkForMEMStrFuncs(self,func_name,caller,argcaller):
        func_callblock=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblock is None:
            return 
        
        result=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        src_argc=self._analysis.project.factory.cc().ARG_REGS[1]
        len_argc=self._analysis.project.factory.cc().ARG_REGS[2]
        
        if argcaller[0] == 'static':
            for callblock in func_callblock:
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,dst_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,src_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'src') )
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,len_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'copy_len') )
        else:
            for callblock in func_callblock:
                for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == dst_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == src_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'src') )
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == len_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'copy_len') )
                    
        return result
    
    
    def _checkForStrFuncs(self,func_name,caller,argcaller):
        func_callblocks=self._analysis.getBlockOFFuctionCall(func_name,caller)
        if func_callblocks is None:
            return 
        
        result=[]
        dst_argc=self._analysis.project.factory.cc().ARG_REGS[0]
        src_argc=self._analysis.project.factory.cc().ARG_REGS[1]
        if argcaller[0] == 'static':
            for callblock in func_callblocks:
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,dst_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                if self._analysis._isAddressLoadIntoReg(callblock.vex,argcaller[1],self._analysis.getRegOffset(callblock.vex,src_argc)):
                    result.append((func_name,callblock.instruction_addrs[-1],'src') )
        else:
            for callblock in func_callblocks:
                for argc in self._analysis.getArgsCC(callblock.vex,self._analysis.getFuncAddress(func_name)):
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == dst_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'dst') )
                    if argc[1].con.value == argcaller[1].con.value and argc[0] == src_argc:
                        result.append((func_name,callblock.instruction_addrs[-1],'src') )
        return result

    
            
    def _isValidAddress(self,callback,caller,value):
        callee=None
        if callback.vex.jumpkind == 'Ijk_Call':
            if len(callback.vex.constant_jump_targets) > 0:
                callee_addr=callback.vex.constant_jump_targets.copy().pop()
            else:
                callee_addr=self._analysis._tryToResolveJump(caller,callback.vex)
            if callee_addr:
                callee=self._analysis.resolveAddrByFunction(callee_addr).name
        if callee is None:
            raise ValueError('Not Valid Callblock')
        
        if self._analysis.targetValueCopyToArgCC(callback.vex,callee,value):
                return True
        return False
        
    def _getCallChain(self,caller):
        result=[]
        uncheckedList=[]

        
        while True:
            main_func=self._analysis.resolveAddrByFunction(self._analysis.getFuncAddress(caller))
            begin=main_func.startpoint.addr
            end=self._analysis.getEndPoint(caller)
            funcs=self._analysis.remvoeSTLFunctionInList(self._analysis.getFunctionCalledBetweenBoundry(caller,begin,end))
            
            for func in funcs:
                tmp_res=(caller,func[1])
                if tmp_res not in result:
                    result.append(tmp_res)
                    uncheckedList.append(func[1])
            
            if len(uncheckedList) == 0:
                break
            caller=uncheckedList.pop()
             
      
        return result
    
    
    def searchInMaps(self,target_name):
        res=[]
        for addr,items in self.malloc_map.items():
            for name,_argcc in items:
                if _argcc[0] == 'static':continue
                if name==target_name:
                    res.append((addr,_argcc))
        return res

    def _checkIsWriteInTargetFunction(self,caller,malloc_pro,target_name=None,target_func=None):
        wr_points=[]
        if target_name is not None:
            if caller  == target_name:
                for addr ,argcc in malloc_pro.items(): 
                    tmp_wr=self._analysis.trackWriteIntoARGCCINCallee(caller,argcc)
                    if len(tmp_wr) > 0 :
                        #tmp_res=(target_name,tmp_wr,addr)
                        tmp_res=(addr,target_name,tmp_wr)
                        wr_points.append(tmp_res)             
        else:            
                
            if target_func is not None:
                name=target_func[1]
            else:
                name=target_name
     
            for begin ,items in malloc_pro.items(): 
                Addrs=self._analysis._mapAddrOfMallocInCallerAndCalle(name,caller,whole=True)
                for i in Addrs:
                    tmp_wr=self._analysis.trackWriteIntoARGCCINCallee(name,i)
                    if len(tmp_wr) > 0 :
                        tmp_res=(begin,name,tmp_wr)
                        wr_points.append(tmp_res)
        return wr_points
    
    
    def _getMallocPosOnArgs(self):
        malloc_args={}
        for addr,specs in self.malloc_map.items():
            for func_name,props in specs:
                if props[0] == 'static': continue
                if func_name != 'main':
                    if 'rbp' not in props[0]:
                        if func_name not in malloc_args.keys():
                            malloc_args[func_name]={}
                            malloc_args[func_name][self._analysis.project.factory.cc().ARG_REGS.index(props[0])+1]=addr
                        else:
                            malloc_args[func_name][self._analysis.project.factory.cc().ARG_REGS.index(props[0])+1]=addr
        return malloc_args
