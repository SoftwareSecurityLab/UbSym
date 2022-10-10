#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 30 22:47:00 2020

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""
from analysis.MCSimulation import MCSimulation
from analysis.simprocedure.ExtractParams import SimExtractParams
from analysis.simprocedure.vul_strcpy import _strcpy_vul
from analysis.Tar3 import runTAR3,_correctInputs,_seperateValues
import angr,claripy,networkx as nx
from analysis.MCSimulation import MCSimulation
from analysis.Units import Units 
from analysis.Cover import Cover
from analysis.TypeUtils import *
import time
import pandas as pd
import pyvex
import subprocess
import collections

class VulAnalyzer(angr.Analysis):
    def __init__(self, cfg_an, checkType, VTree_solo_mode=False, buf_symbolic_bytes=100, max_str_len=100):
        self._init_start = time.time()
        self._cfgAnlyzer = cfg_an
        self._tree = self.project.analyses.VTree(self._cfgAnlyzer, VTree_solo_mode, buf_symbolic_bytes, max_str_len) 

        self._unit_spec=Units(self._cfgAnlyzer)
        heap_wrpoint_res=self._unit_spec.getUnitForHeapBufferOverFlow()
        stack_wrpoint_res,relative_address_res=self._unit_spec.getUnitForStackBufferOverflow()
        
        self._malloc_args=self._unit_spec._getMallocPosOnArgs()
        
        if heap_wrpoint_res is not None:
            self.heap_wrpoints=heap_wrpoint_res
            
        if stack_wrpoint_res is not None:
            self.stack_wrpoints=stack_wrpoint_res 
            self.relative_address=relative_address_res
            
        if checkType > 1 :
            self.PointerNum, self.WFreeaddrs = self.ExtractWfreeAddr(checkType)
            #print(f"PointerNum={self.PointerNum}  WFreeaddrs={self.WFreeaddrs}")
        
        self._init_end = time.time()
            

    def MyGetCallChain(self, funcName, myset):
        myset.add(funcName)
        func=self._cfgAnlyzer.resolveAddrByFunction(self._cfgAnlyzer.getFuncAddress(funcName))
        begin=func.startpoint.addr
        end=self._cfgAnlyzer.getEndPoint(func.name)
        subFunc = self._cfgAnlyzer.remvoeSTLFunctionInList(self._cfgAnlyzer.getFunctionCalledBetweenBoundry(func.name,begin,end))
        for addr, f in subFunc:
            self.MyGetCallChain(f, myset)


    def UseExtractor(self):
        myset = set()
        self.MyGetCallChain('main', myset)

        funcs = list(myset)
        #funcs_address = [self._cfgAnlyzer.getFuncAddress(i) for i in funcs]
        #Args = self._cfgAnlyzer.project.factory.cc().ARG_REGS
        use_list = set()
        for func in funcs: 
            blockCount = self._cfgAnlyzer.functionBlockNum(func)
            for i in range(blockCount):
                vex = self._cfgAnlyzer.getBlockOfFunctionAt(func,i).vex
                rbp_tmp = self._cfgAnlyzer._getRBPTemps(vex)
                for stle_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.Store):
                    stmt_addr = self._cfgAnlyzer.getAddressStatement(vex,stle_stmt)
                    for wr_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                        if 't' + str(wr_stmt.tmp) == str(stle_stmt.addr):
                            if isinstance(wr_stmt.data,pyvex.expr.Binop):
                                if str(wr_stmt.data.args[0]) in rbp_tmp:
                                    for malloc_addr, buffer in self._unit_spec.malloc_map.items():
                                        for func_name, rbp_offset in buffer:
                                            if (func_name == func) and (rbp_offset[1] == wr_stmt.data.args[1]):
                                                if i==0:
                                                    is_push = False
                                                    for get_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                                                        if isinstance(get_stmt.data,pyvex.expr.Get): 
                                                            if ('t' + str(get_stmt.tmp) == str(stle_stmt.data)
                                                            and 't' + str(wr_stmt.tmp) == str(stle_stmt.addr)):
                                                                is_push = True; break                                                 
                                                    if is_push == False:
                                                        use_list.add((func, stle_stmt, i, malloc_addr, stmt_addr))        
                                                elif vex.instruction_addresses[0] == stmt_addr:
                                                    prev_vex = self._cfgAnlyzer.getBlockOfFunctionAt(func,i-1).vex
                                                    if prev_vex.jumpkind == 'Ijk_Call':
                                                        # call_addr = list(prev_vex.constant_jump_targets)[0]
                                                        # must be check
                                                        for get_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                                                            if isinstance(get_stmt.data,pyvex.expr.Get): 
                                                                if 't' + str(get_stmt.tmp) == str(stle_stmt.data):
                                                                    if self._cfgAnlyzer.getRegsName(vex, get_stmt.data.offset) != 'rax':
                                                                        use_list.add((func, stle_stmt, i, malloc_addr, stmt_addr))
                                                                        break
                                                else:
                                                    use_list.add((func, stle_stmt, i, malloc_addr, stmt_addr))
                                else:
                                    for load_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                                        if isinstance(load_stmt.data,pyvex.expr.Load): 
                                            if 't' + str(load_stmt.tmp) == str(wr_stmt.data.args[0]):
                                                for bin_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                                                    if 't' + str(bin_stmt.tmp) == str(load_stmt.data.addr):
                                                        if isinstance(bin_stmt.data,pyvex.expr.Binop):
                                                            if str(bin_stmt.data.args[0]) in rbp_tmp:
                                                                for malloc_addr, buffer in self._unit_spec.malloc_map.items():
                                                                    for func_name, rbp_offset in buffer:
                                                                        if (func_name == func) and (rbp_offset[1] == bin_stmt.data.args[1]):
                                                                            use_list.add((func, stle_stmt, i, malloc_addr, stmt_addr))
                            elif isinstance(wr_stmt.data,pyvex.expr.Load):
                                for wr_stmt2 in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                                    if isinstance(wr_stmt2.data,pyvex.expr.Binop):
                                        if 't' + str(wr_stmt2.tmp) == str(wr_stmt.data.addr):
                                            if str(wr_stmt2.data.args[0]) in rbp_tmp:
                                                for malloc_addr, buffer in self._unit_spec.malloc_map.items():
                                                    for func_name, rbp_offset in buffer:
                                                        if (func_name == func) and (rbp_offset[1] == wr_stmt2.data.args[1]):
                                                            if i==0:
                                                                is_push = False
                                                                for get_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                                                                    if isinstance(get_stmt.data,pyvex.expr.Get): 
                                                                        if ('t' + str(get_stmt.tmp) == str(stle_stmt.data)
                                                                        and 't' + str(wr_stmt.tmp) == str(stle_stmt.addr)):
                                                                            is_push = True; break
                                                                if is_push == False:
                                                                    use_list.add((func, stle_stmt, i, malloc_addr, stmt_addr))         
                                                            elif vex.instruction_addresses[0] == stmt_addr:
                                                                prev_vex = self._cfgAnlyzer.getBlockOfFunctionAt(func,i-1).vex
                                                                if prev_vex.jumpkind == 'Ijk_Call':
                                                                    # call_addr = list(prev_vex.constant_jump_targets)[0]
                                                                    # must be check
                                                                    for get_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                                                                        if isinstance(get_stmt.data,pyvex.expr.Get): 
                                                                            if 't' + str(get_stmt.tmp) == str(stle_stmt.data):
                                                                                if self._cfgAnlyzer.getRegsName(vex, get_stmt.data.offset) != 'rax':
                                                                                    use_list.add((func, stle_stmt, i, malloc_addr, stmt_addr))
                                                            else:
                                                                use_list.add((func, stle_stmt, i, malloc_addr, stmt_addr))

                for load_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                    if isinstance(load_stmt.data,pyvex.expr.Load):
                        loadstmt_addr = self._cfgAnlyzer.getAddressStatement(vex,load_stmt) 
                        temp_list = set()
                        temp_list.add('t' + str(load_stmt.tmp))
                        for bin_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                            if isinstance(bin_stmt.data,pyvex.expr.Binop):
                                if self._cfgAnlyzer.getAddressStatement(vex,bin_stmt) > loadstmt_addr:
                                    if str(bin_stmt.data.args[0]) == 't' + str(load_stmt.tmp):
                                        temp_list.add('t' + str(bin_stmt.tmp))
                                        
                        for load_stmt_2 in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                            if isinstance(load_stmt_2.data,pyvex.expr.Load):
                                loadstmt2_addr = self._cfgAnlyzer.getAddressStatement(vex,load_stmt_2)
                                if loadstmt2_addr > loadstmt_addr:
                                    if str(load_stmt_2.data.addr) in temp_list: 
                                        for wr_stmt in self._cfgAnlyzer.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                                            if isinstance(wr_stmt.data,pyvex.expr.Binop):
                                                if self._cfgAnlyzer.getAddressStatement(vex,wr_stmt) == loadstmt_addr:
                                                    if 't' + str(wr_stmt.tmp) == str(load_stmt.data.addr):
                                                        if str(wr_stmt.data.args[0]) in rbp_tmp:
                                                            for malloc_addr, buffer in self._unit_spec.malloc_map.items():
                                                                for func_name, rbp_offset in buffer:
                                                                    if (func_name == func) and (rbp_offset[1] == wr_stmt.data.args[1]):
                                                                        use_list.add((func, load_stmt_2, i, malloc_addr, loadstmt2_addr))

        func_names = ["printf", "printLine", "printStructLine","printLongLongLine"]

        func_names = {"printLine", "printStructLine","printLongLongLine","printLongLine", "printf"}
        for func_name in func_names:
            for callAddr, function in self._cfgAnlyzer.getAddressOfFunctionCall(func_name) :   # all printf call
                caller = function.name
                if caller in func_names:
                    continue
                #print(f"{func_name} @ {caller} [{callAddr}]")
                func_callblocks = self._cfgAnlyzer.getBlockOFFuctionCall(func_name, caller)    # all block printf call in function
                if func_callblocks is None:
                    continue 
            
                for callblock in func_callblocks: 
                    for argc in self._cfgAnlyzer.getArgsCC(callblock.vex, self._cfgAnlyzer.getFuncAddress(func_name) ):
                        found = False
                        for malloc_addr, mallocObj in self._unit_spec.malloc_map.items():
                            for funcName, argcc in mallocObj :
                                if caller == funcName and argc[1].con.value == argcc[1].con.value :
                                    use_list.add((caller, None, 0, malloc_addr, callAddr))
                                    found = True
                                    break
                            if found :
                                break
        return use_list


    def ExtractWfreeAddr(self, checkType):
        mallocTable = {}
        retVal = {}
        
        #---- adding malloc(1) to dict
        for i, malloc in enumerate(self._unit_spec.malloc_map.items()):
            mallocAddr, status =  malloc
            for funcName, detail in status :
                mallocTable[(funcName, detail[1].con.value)] = i
                retVal[mallocAddr] = (i, '1')
        
        #---- adding free(0) for each pointer  
        freeCnt = { i:0 for i in range(len(self._unit_spec.malloc_map))}
        
        for freeAddr, status in self._unit_spec.free_map.items():
            pointerNo = mallocTable.get( (status[0], status[1][1].con.value) )
            #print(pointerNo, (status[0], status[1][1].con.value))
            retVal[freeAddr] = (pointerNo, '0')
            
            freeCnt[pointerNo] += 1

        #---- adding use(2) for each pointer  
        if checkType == 3 :
            use_list = [list(use) for use in self.UseExtractor()]
            for use in use_list:
                pointerNo = retVal.get(use[3])[0]
                retVal[ use[4] ] = (pointerNo, '2')

        retVal = collections.OrderedDict(sorted(retVal.items()))

        finalRes = {}
        for addr, status in retVal.items() :
            if checkType == 2 and freeCnt[status[0]] < 2 :
                continue
            
            blkAddr = self._cfgAnlyzer.getBlockRelatedToAddr(addr).addr
            #print(hex(blkAddr), status)
            if blkAddr in finalRes :
                for ptrNo, sts in finalRes[blkAddr].items() :
                    if ptrNo == status[0] :
                        finalRes[blkAddr][status[0]] += status[1]
                        break
                else :
                    finalRes[blkAddr][status[0]] = status[1]
                        
            else :
                finalRes[blkAddr] = {status[0] : status[1]}
                
        if checkType == 2 :
            mapper = [ pointerNo[0] for pointerNo in filter(lambda pointer: pointer[1]>=2, freeCnt.items())]
            finalRes = {addr:[(mapper.index(ptrNo), sts )for ptrNo, sts in status.items()] for addr, status in finalRes.items() }
            PointerNum = len(mapper)
        else :
            finalRes = {addr:[(ptrNo, sts )for ptrNo, sts in status.items()] for addr, status in finalRes.items() }
            PointerNum = len(self._unit_spec.malloc_map)
        
        return PointerNum, finalRes


    def ExtractWfreeAddr2(self, checkType):
        allFunc = set()
        for k, v in self._unit_spec.malloc_map.items():
            for item in v :
                allFunc.add(item[0])
        for k, v in self._unit_spec.free_map.items():
            fname, _ = v
            allFunc.add(fname)
                
        malloc_df = pd.DataFrame(index=self._unit_spec.malloc_map.keys() ,columns=allFunc) 

        for k, v in self._unit_spec.malloc_map.items():
            for item in v :
                malloc_df.loc[k, item[0]] = item[1][1].con.value
                
        #---- grouping malloc with same pointer      
        tmp_df = malloc_df[malloc_df.duplicated(keep=False)]
        #dup_malloc = tmp_df.groupby(list(tmp_df)).apply(lambda x: set(x.index))   #.tolist()
        dup_malloc = [set(gp) for gp in tmp_df.groupby(list(tmp_df)).groups.values()]
        # if dup_malloc.empty :
        #     dup_malloc=[]
        # else :
        #     dup_malloc = dup_malloc.tolist()
        res = dup_malloc + [{i} for i in list(malloc_df[~malloc_df.duplicated(keep=False)].index)]
        
        #---- adding free for each pointer     
        for key, val in self._unit_spec.free_map.items():
            malloc_index = set( malloc_df[ malloc_df[ val[0] ]==val[1][1].con.value ].index )
            for i in res:
                if malloc_index.issubset(i) :
                    i.add(key)
                    break
                           
        #---- keep pointer with atleast 2 free   
        if checkType == 2 :        
            res2 = [ i for i in res if sum(j in self._unit_spec.free_map.keys() for j in i)>=2]
        else :
            res2 = res

        PointerNum = len(res2)
        
        resF = {}
        for i, l in enumerate(res2) :
            for j in l :
                resF[self._cfgAnlyzer.getBlockRelatedToAddr(j).addr] = [(i, ("1" if j in self._unit_spec.malloc_map.keys() else "0"))]

        #---- add heap usage
        if checkType == 3:
            use_list = [list(use) for use in self.UseExtractor()]
            for use in use_list:
                Uindex = None
                for i, r in enumerate(res2):
                    if use[3] in r :
                        Uindex = i
                        break
                useBlockaddr = self._cfgAnlyzer.getBlockRelatedToAddr(use[4]).addr
                k = resF.get(useBlockaddr, [] )
                if any([ Uindex==a[0] for a in k]) :
                    k = [(a,'2'+b) if a==Uindex else (a,b) for a,b in k]
                else :
                    k.append((Uindex, '2'))
                resF[useBlockaddr] = k
        
        return PointerNum, resF


    def propWUnits(self):
        units=self._unit_spec.getUnitForDoubleFree(self.PointerNum, self.WFreeaddrs)
        
        print('-'*80)
        reportVul("\Oops, you did not specify the unit name and it's prototype, you can set it with -n and -s options")
        reportBold('-|Critical units are : ')
        for unit in units:
            reportBlue('-'*22+"|{}",unit)
            reportBlue('-'*25+"|{}","You can reach it through these chains :")
            for chain in self._cfgAnlyzer.getCallChain(unit):
                value=chain.replace('-' , '  \u2192 ')
                reportBlue('-'*30+"|{}",value)
        return units


    def propOverflowUnits(self, vul_type):
        if vul_type == "HOF":
            units=set()
            for addr,func,props in self.heap_wrpoints:
                units.add(func) 
  
            reportVul("\Oops, you did not specify the unit name and it's prototype, you can set it with -n and -s options")
            print('-'*80)
            if len(units) > 0:
                reportBold('-|Critical units for heap-based buffer overflow are : ')
                for unit in units:
                    reportBlue('-'*22+"|{}",unit)
                    reportBlue('-'*25+"|{}","You can reach it through these chains :")
                    for chain in self._cfgAnlyzer.getCallChain(unit):
                        value=chain.replace('-' , '  \u2192 ')
                        reportBlue('-'*30+"|{}",value)
            else:
                reportBold('-|There is no critical unit for heap-based buffer overflow!')

        elif vul_type == "SOF":
            units=set()
            for func,addr,props in self.stack_wrpoints:
                units.add(func)

            print('-'*80)
            if len(units) > 0:
                reportBold('-|Critical units for stack-based buffer overflow are : ')
                for unit in units:
                    reportBlue('-'*22+"|{}",unit)
                    reportBlue('-'*25+"|{}","You can reach it through these chains :")
                    for chain in self._cfgAnlyzer.getCallChain(unit):
                        value=chain.replace('-' , '  \u2192 ')
                        reportBlue('-'*30+"|{}",value)  
            else:
                reportBold('-|There is no critical unit for stack-based buffer overflow!')

        return units

    
    def overflowAnalyze(self,unit_protoType,args_index=[],arg_sizes=[],buff_type='heap'):

        _analyze_start = time.time()
        self._prototypes, self.unit=self._setUpFunctionPrototypes(unit_protoType)
        if self._cfgAnlyzer.isReachableFromMain(self.unit) == False:
            raise ValueError('Can not reach the target unit ...')


        mc=MCSimulation('NFACTOR_MC.cfg',nfactor=True)
        if len(args_index) > 0:
            argv={}
            for idx in args_index:
                size=mc.getVarTypes(idx-1)
                argv[idx]=int(size[1])
            self._tree.setupArgv(argv)
        
        print('-'*80)
        reportBold('\nSteps')

        malloc_boundry=self.getMallocsBoundries()
        stack_boundry=self.getStacksBoundries(arg_sizes)

        argStatus=self._prototypes[self.unit]

        heap_wr_points=self._getHeapWritePointAt(self.unit) 
        stack_wr_points=self._getStackWritePointAt(self.unit) 

        reportBlack('-'*4+'| 1.{}','Extracting constraint tree ')
        
        self._tree.sefValspHeap(heap_wr_points)
        self._tree.sefValspStack(stack_wr_points)
        
        self._tree.setMallocBoundry(malloc_boundry)
        self._tree.setStackBoundry(stack_boundry)

        #print("stack_boundry:",stack_boundry)
        
        if self._malloc_args and self.unit in self._malloc_args.keys():
            self._tree.setMallocArgs(self._malloc_args[self.unit])

        malloc_relativeAddr=self._unit_spec.searchInMaps(self.unit)
        stack_buffer_relativeAddr=self._unit_spec.searchInMaps(self.unit)

        stack_buffer_relativeAddr = []
        for func, buffer, wr_list in self.relative_address:
            if func==self.unit:
                stack_buffer_relativeAddr.append((buffer[1].con.value, buffer))

        #print('stack_buffer_relativeAddr:',stack_buffer_relativeAddr)
        malloc_relativeAddr=self._unit_spec.searchInMaps(self.unit)

        self._tree.setUpMallocRelativeAddr(malloc_relativeAddr)
        self._tree.setUpStackBufferRelativeAddr(stack_buffer_relativeAddr)

        pointer_idx,var=self._getBitVectorsAndPonterIdx(self.unit,arg_sizes)
        unit_func=self._cfgAnlyzer.resolveAddrByFunction(self._cfgAnlyzer.getFuncAddress(self.unit))
        st=time.time()
        self._tree.generateForCallable(unit_func,*var,VulnType=buff_type)
        ed=time.time()

        mallocArgsSz=self._getMallocSzForUnit(malloc_boundry,self.unit)
        
        reportBlack('-'*4+'| 2.{}','Applying cover algorithm ')
        coverstartTime=time.time()
        self.cover=Cover(mc,self.project,self._cfgAnlyzer,self._tree,unit_func,unitArgsStatus=argStatus,mallocArgSz=mallocArgsSz)
        result=self.cover.cover(1,pointer_indexes=pointer_idx,args_index=args_index)
        coverendTime=time.time()
        _analyze_end = time.time()
        
        totalTime = (_analyze_end - _analyze_start) + (self._init_end - self._init_start)
        if result == -1:
            reportBold("\nCover algorithm are not appplied")
        else :
            reportBold('\nCover algorithm takes {} seconds to finish'.format(round(coverendTime-coverstartTime)))
        reportBold('\nAnalysis takes {} seconds to finish'.format(round(totalTime)))
        
        
        if len(self._tree._generetedVulConst)>0:
            reportBlack('\nGenerated vulnerability constraints are : ')
            for inode,vul_const in self._tree._generetedVulConst.items():
                reportBlue('-| for node ' + str(inode) , ' ...  ' )
                reportVul('-'*20+'| {}',vul_const)
                
        reportBlack('\nTotal generated vulnerability constraints : {}\n',self._tree._vulConstNumb )    
        
        if len(self._tree._vulReports)==0 and (result and (result == -1 or len(result) == 0)):
            reportBold("Analysis did not found any vulnerabilities")
            return result
        

        if len(self._tree._vulReports) > 0:
            reportBold('\n--|Dicovered vulnerabilities in functions with concrete arguments')
            for report in set(self._tree._vulReports):
                reportVul("---|{}",report)
            if result == -1 :
                return 
        
        
        if result and ( len(result) >0 or len(self.cover._unsats)>0):
            reportBold('Nodes Status :')
            
            nodes=list(self._tree._graph.nodes)
            if len(result) > 0 :
                for inode,inputs in result.items():
                    node=self._tree.getNodeByInode(inode)
                    if len(inputs) > 0:
                        reportBold('\n-|For Node with Inode {} : \n ',inode)
                        
                        reportBold('Number of constraints for this Node {} ',len(node.constraints))
                        reportBold('Number of vulnerability constraints {}\n',len(node._extra_vul_const))
                        
                        for msg in nodes[inode]._vulMsg:
                            reportVul('--|{}',msg)
                        reportBlack('\n\-|You can reach it with these inputs : ')
                        for inp in inputs:
                            reportVul('--|{}',inp)
                            
            if len(self.cover._unsats) > 0:
                reportBold('-|Unsat nodes are :')
                for msg,node_index in self.cover._unsats:
                    node=self._tree.getNodeByInode(node_index)
                    reportBlue('--|{}',msg)
                    reportBlue('----|Number of constraints for this node {} ',len(node.constraints))
                
        return result
                
        
    def analyze(self,unit_protoType,args_index=[],arg_sizes=[], VulnType=2):
        _analyze_start = time.time()
        
        self._prototypes, self.unit=self._setUpFunctionPrototypes(unit_protoType)
        if self._cfgAnlyzer.isReachableFromMain(self.unit) == False:
            raise ValueError('Can not reach the target unit ...')
        
        print('-'*80)
        reportBold('\nSteps')
        
        argStatus=self._prototypes[self.unit]

        reportBlack('-'*4+'| 1.{}','Extracting Constraint tree ')

        if VulnType > 1:
            self._tree.setupWFreeArgs(self.PointerNum, self.WFreeaddrs)

        mc=MCSimulation('NFACTOR_MC.cfg',nfactor=True)
        if len(args_index) > 0:
            argv={}
            for idx in args_index:
                size=mc.getVarTypes(idx-1)
                argv[idx]=int(size[1])
            self._tree.setupArgv(argv)
        
        if self._malloc_args and self.unit in self._malloc_args.keys():
            self._tree.setMallocArgs(self._malloc_args[self.unit])
        
        pointer_idx,var=self._getBitVectorsAndPonterIdx(self.unit,arg_sizes)
        unit_func=self._cfgAnlyzer.resolveAddrByFunction(self._cfgAnlyzer.getFuncAddress(self.unit))
        st=time.time()
        self._tree.generateForCallable(unit_func,*var,VulnType=VulnType)
        ed=time.time()

        #reportBold('\nGenerate tree Takes {} seconds to finish'.format(ed-st))

        mallocArgsSz=None

        reportBlack('-'*4+'| 2.{}','Applying cover algorithm ')
        coverstartTime=time.time()
        self.cover=Cover(mc,self.project,self._cfgAnlyzer,self._tree,unit_func,unitArgsStatus=argStatus,mallocArgSz=mallocArgsSz)
        result=self.cover.cover(1,pointer_indexes=pointer_idx,args_index=args_index)
        coverendTime=time.time()
        _analyze_end = time.time()
        
        totalTime = (_analyze_end - _analyze_start) + (self._init_end - self._init_start)
        if result == -1:
            reportBold("\nCover algorithm were not appplied")
        else :
            reportBold('\nCover algorithm takes {} seconds to finish'.format(round(coverendTime-coverstartTime)))
        reportBold('\nAnalysis takes {} seconds to finish'.format(round(totalTime)))
        
        if len(self._tree._generetedVulConst)>0:
            reportBlack('\nGenerated vulnerability constraints are : ')
            for inode,vul_const in self._tree._generetedVulConst.items():
                reportBlue('-| for node ' + str(inode) , ' ...  ' )
                reportVul('-'*20+'| {}',vul_const)
                
        reportBlack('\nTotal generated Vulnerability constraint : {}\n',self._tree._vulConstNumb )    
        
        if len(self._tree._vulReports)==0 and (result and (result == -1 or len(result) == 0)):
            reportBold("Analysis doesn't found any vulnerability")
            return result
        
        if len(self._tree._vulReports) > 0:
            reportBold('\n--|Dicovered vulnerabilities in functions with concrete arguments')
            for report in set(self._tree._vulReports):
                reportVul("---|{}",report)
            if result == -1 :
                return 
        
        if result and ( len(result) >0 or len(self.cover._unsats)>0):
            reportBold('Nodes Status :')
            
            nodes=list(self._tree._graph.nodes)
            if len(result) > 0 :
                for inode,inputs in result.items():
                    node=self._tree.getNodeByInode(inode)
                    if len(inputs) > 0:
                        reportBold('\n-|For node with inode {} : \n ',inode)
                        
                        reportBold('Number of constraints for this node {} ',len(node.constraints))
                        reportBold('Number of vulnerability constraints {}\n',len(node._extra_vul_const))
                        
                        for msg in nodes[inode]._vulMsg:
                            reportVul('--|{}',msg)
                        reportBlack('\n\-|You can reach it with these inputs : ')
                        
                        for inp in inputs:
                            # with open(f"./Inputs/in{inode}.bin","rb") as in_file :
                            #     data = in_file.read(512)
                            #     outExe = subprocess.run([self.project.filename, data.split(b'\x00')[0]], 
                            #                                                 stdout=subprocess.PIPE,
                            #                                                 stderr=subprocess.PIPE,
                            #                                             )
                            #     if b'double free' in outExe.stderr :
                            #         print(f"Success Input generated for Node {inode}")
                            #     else :
                            #         print(f"Failure Input generated for Node {inode}")
                            
                            reportVul('--|{}',inp)
                            
            if len(self.cover._unsats) > 0:
                reportBold('-|Unsat nodes are :')
                for msg,node_index in self.cover._unsats:
                    node=self._tree.getNodeByInode(node_index)
                    reportBlue('--|{}',msg)
                    reportBlue('----|Number of constraints for this node {} ',len(node.constraints))
                
        return result
                
                   
    def getMallocsBoundries(self):
        result={}
        for addr , func in self._cfgAnlyzer.getAddressOfFunctionCall('malloc'):
            b=self._cfgAnlyzer.getBlockRelatedToAddr(addr) 
            sz=self._cfgAnlyzer.getMallocSize(b.vex,func.name)
            if sz:
                result[addr]=sz
                
        return result


    def getStacksBoundries(self, arg_sizes):
        result={}
        index=0
        for func, buffer, wr_list in self.stack_wrpoints:
            if isinstance(buffer[1], tuple):
                complement = max(arg_sizes)
            else:
                value = buffer[1].con.value
                complement = -(value & 0x80000000) | (value & 0x7fffffff)
            result[func + '-' + str(self.relative_address[index][1][1].con.value)] = abs(complement)
            index += 1
            
        return result    


    def _getBitVectorsAndPonterIdx(self,unit,arg_sizes):
        var=[]
        pointer_index=[]
        pointers=self._prototypes[unit]
        for numb,tp in pointers.items():
            var_name='var_{}'.format(numb)
            sz=None
            if tp == 'charPointer' or tp=='struct':
                sz=arg_sizes[numb-1]
            bit=getSymbolicBV(var_name,tp,size=sz)
            var.append(bit)
            pointer_index.append(numb-1)

        return (pointer_index,var)


    def _getHeapWritePointAt(self,callee):
        result=[]
        for malloc_addr,func_name,wr_list in self.heap_wrpoints:
            if func_name == callee:
                result.append((malloc_addr,wr_list))
                
        return result


    def _getStackWritePointAt(self, callee):
        result=[]
        for func_name,src,wr_list in self.relative_address:
            rbp_offset = src[1].con.value
            if func_name == callee:
                result.append((rbp_offset,wr_list))
                
        return result 
        

    def _setUpFunctionPrototypes(self,protoType):
        pointers={}
        name=protoType[protoType.index(' '):protoType.index('(')]
        protoType=protoType.replace(name,' ')
        name=name.strip()
        tmp_res=angr.types.parse_type(protoType)
        pointers[name]={}
        numb=1
        for arg in  tmp_res.args:
            arg_name=str(arg)
            if '*' in arg_name:
                arg_name=arg_name.replace('*','Pointer')
            pointers.get(name)[numb]=arg_name
            numb=numb+1
        return pointers, name

  
    def _getMallocSzForUnit(self,malloc_boundry,unit):
        if self._malloc_args and  unit in self._malloc_args:
            unitArgMallocSize=self._malloc_args[unit]
            res={}
            for arg_numb,m_addr in unitArgMallocSize.items():
                res[arg_numb]=malloc_boundry.get(m_addr)
            return res

