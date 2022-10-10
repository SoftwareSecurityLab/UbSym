#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jun 11 00:17:30 2020

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""
import networkx as np
import angr,pyvex
from analysis.TypeUtils import *

class CFGPartAnalysis(angr.Analysis):
    
    def __init__(self):
        self.cfg=self.project.analyses.CFGFast(data_references=True)
    
    
    def getFuncAddress(self, funcName, plt=None ):
        """
            getting address of an function by it's name
        """
        found = [
            addr for addr,func in self.cfg.kb.functions.items()
            if funcName == func.name and (plt is None or func.is_plt == plt)
            ]
        if len( found ) > 0:
            #print("Found "+funcName+"'s address at "+hex(found[0])+"!")
            return found[0]
        else:
            raise Exception("No address found for function : "+funcName)


    def functionBlockNum(self, funcName):
        blockCount = 0 
        func=self.resolveAddrByFunction(self.getFuncAddress(funcName))
        for block in func.blocks:
            blockCount = blockCount + 1
        
        return blockCount
            
    def isFunctionAddr(self,addr):
        """
            it checks given addr is a function addr
        """
        for func_addr,func in self.cfg.kb.functions.items():
            if func_addr == addr:
                return True
        return False
    
    def getFunctions(self):
        """
        get All functions of an project with it's address
        ex:(address,function object)
        """
        result=list()
        for addr,func in self.cfg.kb.functions.items():
            result.append((addr,func))
            
        return result
    
    def isReachableFromMain(self,func_name):
        """
         This function is reachable from main or not
        """
        call_chain=self.getCallChain(func_name)
        for call in call_chain:
            if 'main' in call:
                return True
        return False
    
    def _getRBPTemps(self,vex):
        rbp_tmp=self.listOfWrTmpWithRegName(vex,'rbp')
        rbps=[]
        if len(rbp_tmp) > 0:
            rbp_tmp='t'+str(rbp_tmp[0].tmp)
            rbps.append(rbp_tmp)
            bio_cmd=[]
            for rbp_put in self._getListPutStmtByRegName(vex,'rbp'):
                if isinstance(rbp_put.data,pyvex.expr.RdTmp):
                    rbps.append(str(rbp_put.data))
        return rbps
    
    def getArgvAddrsOnStack(self):
        vex=self.getBlockOfFunctionAt('main',0).vex
        argv_reg=self.project.factory.cc().ARG_REGS[1]
        rbps=self._getRBPTemps(vex)
                
        for wr_stmt in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(wr_stmt.data,pyvex.expr.Get) and (wr_stmt.data.offset == self.getRegOffset(vex,argv_reg)):
                get_tmp='t'+str(wr_stmt.tmp)
                for st_stmt in self._listOfStoreWithTempNameSRC(vex,get_tmp):
                    if isinstance(st_stmt.addr,pyvex.expr.RdTmp):
                        st_tmp=str(st_stmt.addr)
                        target_wr=self.targetWrTempByTempName(vex,st_tmp)
                        if isinstance(target_wr.data,pyvex.expr.Binop):
                            arg1,arg2=target_wr.data.args
                            if isinstance(arg1,pyvex.expr.RdTmp) and 't'+str(arg1.tmp) in rbps:
                                return ('rbp',arg2,target_wr.data.op)

    def getArgsOFFunction(self, vex):
        cnt = 0
        result = []
        rbp = self._getRBPTemps(vex)
        regs = self.project.factory.cc().ARG_REGS
        reg_offset = [self.getRegOffset(vex,reg) for reg in regs]
        for get_stmt in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(get_stmt.data,pyvex.expr.Get):
                if get_stmt.data.offset in reg_offset:
                    for stle_stmt in self.getVexListCommand(vex,pyvex.IRStmt.Store):
                        if str(stle_stmt.data) == 't' + str(get_stmt.tmp):
                            for binop_stmt in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                                if isinstance(binop_stmt.data,pyvex.expr.Binop):
                                    if 'Iop_Add' in binop_stmt.data.op or 'Iop_Sub' in binop_stmt.data.op:
                                        if 't' + str(binop_stmt.tmp) == str(stle_stmt.addr):
                                            if str(binop_stmt.data.args[0]) in rbp:
                                                result.append((regs[reg_offset.index(get_stmt.data.offset)], binop_stmt.data.args[1]))
                                                cnt = cnt + 1
        return cnt, result


    def checkForArgvAsArgument(self,callee):
         argv=self.getArgvAddrsOnStack()
         target_ARGS=self.project.factory.cc().ARG_REGS
         maps={}
         if argv is None:
             return 
         for block in self.getBlockOFFuctionCall(callee,'main'):
             bio_ops=[]
             for wr_stmt in self.getVexListCommand(block.vex,pyvex.IRStmt.WrTmp):
                if isinstance(wr_stmt.data,pyvex.expr.Binop) and isinstance(wr_stmt.data.args[1],pyvex.expr.Const):
                    if wr_stmt.data.args[1].con.value == argv[1].con.value:
                        wr_tmp='t'+str(wr_stmt.tmp)
                        for load_stmt in self._listOfLoadwithTempNameSrc(block.vex,wr_tmp):
                            bio_ops.append('t'+str(load_stmt.tmp))
             for wr_stmt in self.getVexListCommand(block.vex,pyvex.IRStmt.WrTmp):
                if isinstance(wr_stmt.data,pyvex.expr.Binop) and isinstance(wr_stmt.data.args[0],pyvex.expr.RdTmp):
                    if str(wr_stmt.data.args[0]) in bio_ops:
                        if isinstance(wr_stmt.data.args[1],pyvex.expr.Const):
                            value=wr_stmt.data.args[1].con.value
                            argv_index=int(value/8)
                            target_load=self._listOfLoadwithTempNameSrc(block.vex,'t'+str(wr_stmt.tmp))
                            if len(target_load)> 0:
                                load_tmp='t'+str(target_load[0].tmp)
                                for arg in  target_ARGS:
                                    put_stmt=self._getLastPutStmtByOffset(block.vex,self.getRegOffset(block.vex,arg))
                                    if put_stmt and  isinstance(put_stmt.data,pyvex.expr.RdTmp) and str(put_stmt.data) == load_tmp:
                                        if block.addr not in maps.keys():
                                            maps[block.addr]=[]
                                        maps[block.addr].append((argv_index,self.getRegsName(block.vex,put_stmt.offset)))
         return maps
     



        
    def resolveAddrByFunction(self,addr):
        """
        resolve the address with it's function .any address blong to the function
        """                
        for i in self.getFunctions():
            r=i[1]
            for block in r.blocks:
                try:
                    if addr in block.instruction_addrs:
                        return r
                except angr.errors.SimTranslationError:
                    pass
                
    def getBlockRelatedToAddr(self,addr):
        """ 
        return block related to an address
        """
        try:
            func=self.resolveAddrByFunction(addr)
            for blck in func.blocks:
                if addr in blck.instruction_addrs:
                    return blck
        except:
            return None
        
        
        
    def getStoreInTargetAddr(self,addr,vex):
        """
        if an store is in a address vex commands this function returns it
        """
        for stmt in vex.statements:
            if stmt.tag == 'Ist_IMark':
                if  stmt.addr == addr:
                    flag=True
                else:
                    flag=False
            if flag:
               if isinstance(stmt,pyvex.IRStmt.Store):
                   return stmt
               
        
    def isMallocReterned(self,rel_addr,func):
        """
            this function checked that the malloc values retured from this function
        """
        for endpoint in func.endpoints:
            end_b=self.getBlockRelatedToAddr(endpoint.addr)
            puts=self._getListPutStmtByRegName(end_b.vex,self.project.factory.cc().RETURN_VAL.reg_name)
            if len(puts)>0:
                ret_puts=puts[0]
                if isinstance(ret_puts.data , pyvex.expr.RdTmp):
                    ret_tmp=str(ret_puts.data)
                    tr_wr=self.targetWrTempByTempName(end_b.vex,ret_tmp)
                    if tr_wr and  isinstance(tr_wr.data,pyvex.expr.Load) and isinstance(tr_wr.data.addr,pyvex.expr.RdTmp):
                        bio_op=self.targetWrTempByTempName(end_b.vex,str(tr_wr.data.addr))
                        if isinstance(bio_op,pyvex.IRStmt.WrTmp) and isinstance(bio_op.data,pyvex.expr.Binop) and isinstance(bio_op.data.args[1],pyvex.expr.Const):
                            if bio_op.data.args[1].con.value == rel_addr:
                                return end_b.addr
    
    def getEndPoint(self,target_name):
        """
        get endpoints of a function with lower address from other endpoints
        """
        target=self.resolveAddrByFunction(self.getFuncAddress(target_name))
        addr=0x0
        for node in target.endpoints:
            if addr < node.addr:
                addr=node.addr
        
        return  addr
    
        
    def getCaller(self,func_name):
        """
        it search throw all functions and returns caller functions of this function
        """
        result=list()
        functions=self.getFunctions()
        for func in functions:
            call_sites=list(func[1].get_call_sites())
            for site in call_sites:
                block=self.project.factory.block(site)
                vex=block.vex
                if vex.jumpkind == 'Ijk_Call':
                    jump=self._getCallPROPSFromCFG(block.addr)
                    if jump:
                        jmp_node,jmp_type=jump
                        if jmp_node.is_simprocedure and 'Unresolvable' in jmp_node.name:
                            addr=self._tryToResolveJump(func[1].name,vex)
                            if addr:
                                if self.cfg.kb.functions[addr].name == func_name:
                                    result.append(func)
                        elif self.cfg.kb.functions[jmp_node.addr].name == func_name:
                            result.append(func)
                                                                
        return result
    
    
    def _getCallPROPSFromCFG(self,addr):
        target_node=self._getNodeInCFGGraph(addr)
        if target_node:
            jump=target_node.successors_and_jumpkinds()
            if len(jump) == 1:
                return jump[0]
    
    
    def _getNodeInCFGGraph(self,addr):
        for node in self.cfg.graph.nodes:
            if addr in node.instruction_addrs:
                return node
                
    def getCallChain(self,target_leaf):
        """
            given the target leaf it resturns all call chain that get to this point
        """
        result=[]
        tmp_res=[target_leaf]
        while len(tmp_res) >0 :
            c=tmp_res.pop()
            if '-' in c:
                cname=c[0:c.index('-')]
            else:
                cname=c
            caller=self.getCaller(cname)
            if len(caller) > 0:
                for item in caller:
                    tmp_res.append(item[1].name + '-' + c)
            else:
                result.append(c)
        return result

    

    def getCFGFast(self):
        """
        returns cfg
        """    
        return self.cfg
                
    
    def getAllPaths(self,G):
        """
            get All path of an DiGraph
        """
        roots = (v for v, d in G.in_degree() if d == 0)
        leaves = [v for v, d in G.out_degree() if d == 0]
        all_paths = []
        for root in roots:
            paths = np.all_simple_paths(G, root, leaves)
            all_paths.extend(paths)
            
        return all_paths
    
    
    def getBlockOfFunctionAt(self,func_name,at):
        """
        return the i'block of function given it's name and block position
        """
        func=self.resolveAddrByFunction(self.getFuncAddress(func_name))
        result=list()
        for  item in func.blocks:
            result.append(item)
        
        return result[at]
    
    
    def getAddressOfFunctionCall(self,func_name,dict_type=False):
        """
        returns address witch the target function is called 
        """
        if dict_type:
            result=dict()
        else:
            result=set()
        callers=self.getCaller(func_name)
        if len(callers)>0:
            for func in callers:
                addr=self.getFuncAddress(func_name)
                for i in func[1].blocks:
                    tmp_vex=i.vex
                    if tmp_vex.jumpkind == 'Ijk_Call':
                        jump=self._getCallPROPSFromCFG(i.addr)
                        if jump:
                            jmp_node,jmp_type=jump
                            res_addr=None
                            if jmp_node.is_simprocedure and 'Unresolvable' in jmp_node.name:
                                res_addr=self._tryToResolveJump(func[1].name,i.vex)
                            if (jmp_node.addr == addr) or res_addr:
                                if dict_type:
                                    key=func[1]
                                    value=tmp_vex.instruction_addresses[len(tmp_vex.instruction_addresses)-1]
                                    if key not in result.keys():
                                        result[key]=list()
                                    if value not in result[key]:
                                        result[key].append(value)
                                    
                                else:
                                    result.add((tmp_vex.instruction_addresses[len(tmp_vex.instruction_addresses)-1],func[1]))
        if dict_type:
            return result
        return list(result)
    
    
    def getBlockOFFuctionCall(self,callee_name,caller_name):
        """
            return blocks witch callee callled in caller function
        """
        addrs=self.getAddressOfFunctionCall(callee_name)
        result=list()
        if len(addrs) == 0:
            return result
        for item in addrs:
            addr,caller=item
            if caller.name == caller_name:
                for i in caller.blocks:
                    if addr in i.instruction_addrs:
                        result.append(i)
    
        return result


    def getRegsName(self,vex,offset):
        """
        given vex and offset of an register it returns register name for that offset
        """
        for  j in vex.arch.register_list: 
            if offset is j.vex_offset:
                 return j.name
             
                
    def getRegOffset(self,vex,reg_name):
        """
        return register offset of an register by it's name in an vex IRSB
        """
        for  j in vex.arch.register_list: 
            if j.name == reg_name:
                return j.vex_offset 


    def getVexListCommand(self,vex,vexType):
        """
        return list of Statement with type vexType
        """
        result=list()
        for i in vex.statements:
            if isinstance(i,vexType):
                result.append(i)

                    
        return result
    
    def getAddressStatement(self,vex,stmt):
        """
        return address of block with stmt belongs to
        """
        addr=None
        for i in vex.statements:
            if isinstance(i,pyvex.IRStmt.IMark):
                addr=i.addr
            if stmt is i:
                return addr
            
        return None


    def listOfTempStmt(self,v,target):
        """
        list of statements withch target temp is part of it
        """
        import re
        result=list()
        for i in v.statements:
            tmp=i.__str__()
            if re.match(".*"+target+"\\D.*|.*"+target +"$",tmp) is None:
                continue
            result.append(i)
        return result


    def listOfWrTmpWithRegName(self,vex,reg_name):
        """
        returns list of Get Statement with offset of target register
        """
        tmp=self.getVexListCommand(vex,pyvex.IRStmt.WrTmp)
        getList=list()
        for i in tmp:
            if i.data.tag == 'Iex_Get':
                getList.append(i)
    
        result=list()
        for i in getList:
            offset=i.data.offset
            name=self.getRegsName(vex,offset)
            if reg_name == name:
                result.append(i)
                
        del(getList)
        return result
    
    def listOfEffectedTmpWithTargetTemp(self,vex,tmp_name,consider_stores=True):
        """
        returns list of stmts witch effected with target tmp in the rhs of stmt
        """
        tmp=self.listOfTempStmt(vex,tmp_name)
        result=list()
        for i in tmp:
            if isinstance(i,pyvex.IRStmt.WrTmp):
                if 't'+str(i.tmp) != tmp_name:
                    result.append('t'+str(i.tmp))
            elif consider_stores and isinstance(i,pyvex.IRStmt.Store):
                if isinstance(i.data,pyvex.expr.RdTmp):
                    if 't'+str(i.data.tmp) == tmp_name: 
                        if isinstance(i.addr,pyvex.expr.RdTmp):
                            result.append('t'+str(i.addr.tmp))
            elif isinstance(i,pyvex.stmt.Put):
                if isinstance(i.data,pyvex.expr.RdTmp):
                    if 't'+str(i.data.tmp) == tmp_name:
                        if isinstance(i.offset,pyvex.expr.RdTmp):
                            result.append('t'+str(i.addr.tmp))

        return result   
    
    def targetWrTempByTempName(self,vex,tmp_name):
        """
         returns WrStatement with it's taget is target temp
        """
        tmp=self.listOfTempStmt(vex,tmp_name)
        result=None
        for i in tmp:
            if isinstance(i,pyvex.IRStmt.WrTmp):
                if 't'+str(i.tmp) == tmp_name:
                    result=i
        
        return result
    
    def listOfEffectedTempBy(self,vex,tmp_name):
        """
        returns chain of temp variables withch effected with target temp
        """
        effected=self.listOfEffectedTmpWithTargetTemp(vex,tmp_name)
        target=effected.copy()
        blocklist=list()
        while len(target) > 0:
            i=target.pop()
            blocklist.append(i)
            tmp=self.listOfEffectedTmpWithTargetTemp(vex,i)
            for item in tmp:
                if item not in effected:
                    effected.append(item)
                if item not in blocklist and item not in target:
                    target.append(item)
                    #blocklist.append(item)
        del(blocklist)     
      
        return effected
    
    
    def storeEffectedByReg(self,vex,reg_name):
        """
        returns list of stores witch effected by target register
        """        
        result=list()
        reg_wr=self.listOfWrTmpWithRegName(vex,reg_name)
        if len(reg_wr) > 0:
            reg_wr=reg_wr[0]
        else:
            return result
        temp_name='t'+str(reg_wr.tmp)
        effected_temps=self.listOfEffectedTempBy(vex,temp_name)
        stores=self.getVexListCommand(vex,pyvex.IRStmt.Store)
        if len(stores) > 0:
            for item in stores:
                if isinstance(item.addr,pyvex.IRExpr.RdTmp):
                    target='t'+str(item.addr.tmp)
                    if target in effected_temps:
                        result.append(item)
                        
        return result


    def _getDSTOfRetValue(self,vex,target_reg='rax'):
        '''
        take an vex block and return
        ('rbp:t4', <pyvex.expr.Const at 0x7fd09da76eb8>, 'Iop_Add64')
        where const is location which deffer from rbp in stack 
        it means :
            t=add64(rbp,const)
            store(t)=rax or eax
        '''
        rax_tmp=self.listOfWrTmpWithRegName(vex,target_reg)
        if len(rax_tmp) == 0:
            return None
        else:
            rax_tmp=rax_tmp[0].tmp
        rbp_tmp=self.listOfWrTmpWithRegName(vex,'rbp')
        if len(rbp_tmp) == 0:
            return None
        else:
            rbp_tmp=rbp_tmp[0].tmp
            
        effected_rax=self.listOfEffectedTmpWithTargetTemp(vex,'t'+str(rax_tmp))
        undirectEAX=list()
        if len(effected_rax)==1:
            tmp_tmp=effected_rax[0]
            tmp_stmt=self.targetWrTempByTempName(vex,tmp_tmp)
            if isinstance(tmp_stmt,pyvex.IRStmt.WrTmp):
                if isinstance(tmp_stmt.data, pyvex.expr.Unop) and tmp_stmt.data.op == 'Iop_64to32':
                    undirectEAX.append(tmp_tmp)
                    for i in self.listOfEffectedTmpWithTargetTemp(vex,tmp_tmp):
                        undirectEAX.append(i)
                             
        target_store=None
        for i in self.getVexListCommand(vex,pyvex.IRStmt.Store):
            if isinstance(i.data,pyvex.expr.RdTmp):
                if i.data.tmp==rax_tmp or ('t'+str(i.data.tmp) in undirectEAX):
                    target_store=i
        
        result=None
        if target_store is not None:
            dst_store=target_store.addr.tmp
            target_cmd=self.targetWrTempByTempName(vex,'t'+str(dst_store))
            if isinstance(target_cmd.data,pyvex.expr.Binop):
                if 'Iop_Add' in target_cmd.data.op or 'Iop_Sub' in target_cmd.data.op:
                    tmp_var=target_cmd.data.args[0].tmp
                    if tmp_var == rbp_tmp:
                        result=('rbp:t'+str(rbp_tmp),target_cmd.data.args[1],target_cmd.data.op)
        
        return result
    
    
    
    def getRetStoreLocOnStackOfFunction(self,callee,caller):
        '''
        this function return places in stack where return value of callee is store ,if there is one.
        return's' :
            {0x400818: ('rbp:t4', <pyvex.expr.Const at 0x7fd09da76eb8>, 'Iop_Add64')}
            0x400818 -> where called is called
            ('rbp:t4', <pyvex.expr.Const at 0x7fd09da76eb8>, 'Iop_Add64') -> where in stack is retured value stored.       
        '''
        result=list()
        called_addr=None
        caller_addr=self.getFuncAddress(callee)

        for func,addrs in self.getAddressOfFunctionCall(callee,dict_type=True).items():
            if func.name == caller:
                called_addr=addrs
                break
        
        if called_addr:
            for addr in called_addr:
                next_block=self._getNextBlock(addr,last=True)
                if next_block is not None:
                    tmp_r={}
                    tmp_r[addr]=self._getDSTOfRetValue(next_block.vex)
                    result.append(tmp_r)
        
        return result
    
    def _getNextBlock(self,addr,last=False):
        """
         it return next block base on Address
        """
        if last == False:
            addr=self.getBlockRelatedToAddr(addr).instruction_addrs[-1]
            
        while True:
            addr=addr+1
            res=self.getBlockRelatedToAddr(addr)
            if res is not None :
                return res
            
        return None

    
    def _getLastPutStmtByOffset(self,vex,offset):
        """
        return last put statement relative to target register offset
        """
        puts=self.getVexListCommand(vex,pyvex.IRStmt.Put)
        puts.reverse()
        for i in puts:
            if i.offset == offset:
                return i
        
        return None
    
    def _getListPutStmtByRegName(self,vex,reg_name):
        """
        return list of put statement relative to target register name
        """
        result=list()
        puts=self.getVexListCommand(vex,pyvex.IRStmt.Put)
        taeget_offset=self.getRegOffset(vex,reg_name)
        for i in puts:
            if i.offset == taeget_offset:
                result.append(i)
                
        return result
    
    def _trackInputOfFuncionCall(self,vex,input_number,target_fAddr,just_index=False):
        '''
            this function takes an vex block and check target function is called in that block
            and extracted regcc where used and copies values into before function call
            where input_number show which argcc we intersted in.
            
            first for every regcc checks:
            puts(regcc)=t --> t=(add or sub)(rbp,cons)
            where t is in a bio operation and one side of bio opr is rbp register which means a location of stack copies in regcc
            or second
            it exract effected list of rbp then it get bio opetations thet one side of it is in the list
            then if wr_target of t is load operation and the load src of that operation is in the effected list
            of one bio opr in list of bio operations then thats ok
            
            thrid possibility is when we copy an constand in to regcc
            
            return :
                ('rdi', <pyvex.expr.Const at 0x7fd09daa5108>, 'Iop_Add64')
                copy in rdi value of add(rbp,cons) 
        '''
        if target_fAddr not in vex.constant_jump_targets_and_jumpkinds.keys():
            if target_fAddr in vex.constant_jump_targets_and_jumpkinds.keys() and vex.constant_jump_targets_and_jumpkinds[target_fAddr] != 'Ijk_Call':
                print('Not Found, There is No Such Function Call In This Block ')
                return None
            else:
                jump=self._getCallPROPSFromCFG(vex.addr)
                if jump:
                    jmp_node,jmp_tp=jump
                    target_addr=jmp_node.addr
                    if jmp_node.is_simprocedure and 'Unresolvable' in jmp_node.name:
                        caller=self.resolveAddrByFunction(vex.addr)
                        addr=self._tryToResolveJump(caller.name,vex)
                        if addr:
                            target_addr=addr
                    if target_fAddr != target_addr:
                        return None
                else:
                    return None 

        rbp_tmp_list=self._getRBPTemps(vex)
        if len(rbp_tmp_list) == 0:
            return None

        result=None

        for rbp_tmp in rbp_tmp_list:
            for i in self.getVexListCommand(vex,pyvex.IRStmt.Put):
                cc_arg=self.project.factory.cc().ARG_REGS[input_number]
                if self.getRegsName(vex,i.offset) is  cc_arg: 
                    if isinstance(i.data,pyvex.expr.RdTmp):
                        target_tmp=i.data.tmp
                        wr_target=self.targetWrTempByTempName(vex,'t'+str(target_tmp))
                        if isinstance(wr_target.data,pyvex.expr.Binop ):
                            if 'Iop_Add' in wr_target.data.op or 'Iop_Sub' in wr_target.data.op:
                                tmp_var=wr_target.data.args[0].tmp
                                if 't'+str(tmp_var) == rbp_tmp:
                                    result=(cc_arg,wr_target.data.args[1],wr_target.data.op)
                                else:
                                    if isinstance(wr_target.data.args[0],pyvex.expr.RdTmp):
                                        index=wr_target.data.args[1]
                                        wr_target=self.targetWrTempByTempName(vex,str(wr_target.data.args[0]))
                                        result=self._extraCheckForTrackin(rbp_tmp,wr_target,vex,cc_arg)
                                        if result is not None:
                                            if just_index and isinstance(index,pyvex.expr.Const):
                                                return (result[0],index) 
                        else:
                            if just_index:
                                return None
                            result=self._extraCheckForTrackin(rbp_tmp,wr_target,vex,cc_arg)
                    elif isinstance(i.data,pyvex.expr.Const):
                        if just_index:
                            return None
                        if self._getLastPutStmtByOffset(vex,i.offset) is i:
                            result=(cc_arg,i.data,i.data.tag)
        return result
    
    def _extraCheckForTrackin(self,rbp_tmp,wr_target,vex,cc_arg):
        result =None
        rbp_effected=self.listOfEffectedTempBy(vex,rbp_tmp)
        rbp_effected.append(rbp_tmp)
        
        bio_opr=[]
        for i in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(i.data,pyvex.expr.Binop) and isinstance(i.data.args[0],pyvex.expr.RdTmp):
                if 't'+str(i.data.args[0].tmp) in rbp_effected:
                    bio_opr.append(i)
       
                                
        if isinstance(wr_target.data,pyvex.expr.Load):
            if isinstance(wr_target.data.addr,pyvex.expr.RdTmp):
                load_src=wr_target.data.addr.tmp
                for bio in bio_opr:
                    bio_arg1=bio.tmp
                    bio_arg1_effected=self.listOfEffectedTempBy(vex,'t'+str(bio_arg1))
                    if load_src == bio_arg1 or 't'+str(load_src) in bio_arg1_effected:
                        result=(cc_arg,bio.data.args[1],bio.data.op)
                        break
                    
        elif isinstance(wr_target.data, pyvex.expr.Unop):
            if isinstance(wr_target.data.args[0],pyvex.expr.RdTmp):
                uno_tmp=str(wr_target.data.args[0])
                for bio in bio_opr:
                    if isinstance(bio.data.args[0],pyvex.expr.RdTmp):
                        bio_tmp='t'+str(bio.tmp)
                        bio_effected_list=self.listOfEffectedTempBy(vex,bio_tmp)
                        bio_effected_list.append(bio_tmp)
                        if uno_tmp in bio_effected_list:
                            result=(cc_arg,bio.data.args[1],bio.data.op)  
                            break 

        return result
 
                                                         
 
    def get_WrTmp_Binops(self, callblock, src_offset):
        vex = callblock.vex
        instructions = []
        for wr_stmt in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(wr_stmt.data,pyvex.expr.Binop) and ('Iop_Add' in wr_stmt.data.op or 'Iop_Sub' in wr_stmt.data.op):
                if 't' not in str(wr_stmt.data.args[1]):
                    if wr_stmt.data.args[1].con.value == src_offset:
                        instructions.append(wr_stmt)
        return instructions

 
    def get_WrTmp_Binops_t(self, callblock, temp):
        vex = callblock.vex
        instructions = []
        for wr_stmt in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(wr_stmt.data,pyvex.expr.Binop) and ('Iop_Add' in wr_stmt.data.op or 'Iop_Sub' in wr_stmt.data.op):
                if 't' + str(wr_stmt.tmp) == temp:
                    instructions.append(wr_stmt)
        return instructions

 
    def get_WrTmp_Get_t(self, callblock, temp):
        vex = callblock.vex
        instructions = []
        for wr_stmt in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(wr_stmt.data,pyvex.expr.Get):
                if 't' + str(wr_stmt.tmp) == temp:
                    instructions.append(wr_stmt)
        return instructions


    def get_WrTmp_Load(self, callblock, temp):
        vex = callblock.vex
        instructions = []
        for load_stmt in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(load_stmt.data,pyvex.expr.Load): 
                if str(load_stmt.data.addr) == temp:
                    instructions.append(load_stmt)
        return instructions

    def get_Store(self, callblock, temp):        
        vex = callblock.vex
        instructions = []
        for stle_stmt in self.getVexListCommand(vex,pyvex.IRStmt.Store):
            if str(stle_stmt.addr) == temp:
                instructions.append(stle_stmt)
        return instructions

    def get_WrTmp_Load_t(self, callblock, temp):
        vex = callblock.vex
        instructions = []
        for load_stmt in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(load_stmt.data,pyvex.expr.Load): 
                if 't' + str(load_stmt.tmp) == temp:
                    instructions.append(load_stmt)
        return instructions

    def check_argv(self, src_offset):
        init_block = self.getBlockOfFunctionAt("main", 0)
        init_block.pp()

    def find_pointer_rec(self, addr, callblock, func_name, src_offset):
        blockNum = self.functionBlockNum(func_name)
        regs = self.project.factory.cc().ARG_REGS
        for i in range(blockNum):
            if self.getBlockOfFunctionAt(func_name, i).instruction_addrs[-1] <= callblock.instruction_addrs[-1]:
                last_block = self.getBlockOfFunctionAt(func_name, i)
                last_vex = last_block.vex
                rbp_tmp = self._getRBPTemps(last_vex)
                WrTmp_Binops = self.get_WrTmp_Binops(last_block, src_offset)
                for wr_stmt2 in WrTmp_Binops:
                    wr_stmt2_addr = self.getAddressStatement(last_vex, wr_stmt2)
                    if wr_stmt2_addr < addr:
                        Stores = self.get_Store(last_block, 't' + str(wr_stmt2.tmp))
                        for stle_stmt in Stores:
                            stle_stmt_addr = self.getAddressStatement(last_vex, stle_stmt)
                            if stle_stmt_addr >= wr_stmt2_addr and stle_stmt_addr < addr:
                                WrTmp_Binops2 = self.get_WrTmp_Binops_t(last_block, str(stle_stmt.data))
                                for wr_stmt3 in WrTmp_Binops2:
                                    if str(wr_stmt3.data.args[0]) in rbp_tmp:
                                        return (wr_stmt3.data.args[1], last_block, func_name, None)

                                WrTmp_Loads2 = self.get_WrTmp_Load_t(last_block, str(stle_stmt.data))
                                for load_stmt2 in WrTmp_Loads2:
                                    WrTmp_Binops2 = self.get_WrTmp_Binops_t(last_block, str(load_stmt2.data.addr))
                                    for wr_stmt3 in WrTmp_Binops2:
                                        if str(wr_stmt3.data.args[0]) in rbp_tmp:
                                            return (wr_stmt3.data.args[1], last_block, func_name, None)


                                WrTmp_Gets = self.get_WrTmp_Get_t(last_block, str(stle_stmt.data))                                
                                callers = self.getCaller(func_name)
                                for wr_stmt3 in WrTmp_Gets:
                                    get_offset = wr_stmt3.data.offset
                                    if self.getRegsName(callblock.vex,get_offset) in regs:
                                        if func_name == 'main':
                                             return (wr_stmt2.data.args[1], "Argv", None, None)

                                        for c in callers:
                                            callblocks = self.getBlockOFFuctionCall(func_name,c[1].name)
                                            for cb in callblocks:
                                                caller_rbp_tmp = self._getRBPTemps(cb.vex)
                                                put=self._getLastPutStmtByOffset(cb.vex,get_offset)
                                                put_addr = self.getAddressStatement(cb.vex, put)
                                                if put is not None:
                                                    WrTmp_Binops2 = self.get_WrTmp_Binops_t(cb, str(put.data))
                                                    for wr_stmt3 in WrTmp_Binops2:
                                                        if str(wr_stmt3.data.args[0]) in caller_rbp_tmp:
                                                            return (wr_stmt3.data.args[1], cb, c[1].name, None)

                                                    WrTmp_Loads2 = self.get_WrTmp_Load_t(cb, str(put.data))
                                                    for load_stmt2 in WrTmp_Loads2:
                                                        WrTmp_Binops2 = self.get_WrTmp_Binops_t(cb, str(load_stmt2.data.addr))
                                                        for wr_stmt3 in WrTmp_Binops2:
                                                            if str(wr_stmt3.data.args[0]) in caller_rbp_tmp:
                                                                return (wr_stmt3.data.args[1], cb, c[1].name, wr_stmt3)
                                                            else:
                                                                for l_stmt in self.get_WrTmp_Load_t(cb, str(wr_stmt3.data.args[0])):
                                                                    for b_op in self.get_WrTmp_Binops_t(cb, str(l_stmt.data.addr)):
                                                                        if str(b_op.data.args[0]) in caller_rbp_tmp:
                                                                            return (b_op.data.args[1], cb, c[1].name, b_op)
                       
        return (None, None, None, None)


    def _is_pointer(self, callblock, func_name, src_offset):
        vex = callblock.vex
        prev = None
        WrTmp_Binops = self.get_WrTmp_Binops(callblock, src_offset)
        for wr_stmt in WrTmp_Binops:
            temp = 't' + str(wr_stmt.tmp)
            WrTmp_Loads = self.get_WrTmp_Load(callblock, temp)
            for load_stmt in WrTmp_Loads:
                prev = None
                wr_stmt3, last_block, f_name, m = self.find_pointer_rec(self.getAddressStatement(vex,wr_stmt), callblock, func_name, src_offset) 
                while wr_stmt3 is not None:
                    if last_block == 'Argv':
                        return ("Argv", wr_stmt3)
                    prev = wr_stmt3
                    if m is None:
                        wr_stmt3, last_block, f_name, m = self.find_pointer_rec(self.getAddressStatement(vex,wr_stmt), last_block, f_name, wr_stmt3.con.value)
                    else:
                        wr_stmt3, last_block, f_name, m = self.find_pointer_rec(self.getAddressStatement(last_block.vex,m), last_block, f_name, wr_stmt3.con.value)
     
            if prev is not None:     
                return (prev)
               
        return False
   
    def getArgsCC(self,vex,target_fAddr):
        '''
         this funcion try to extract all argcc where a value is copied into before calling target function
         
         warrning: this doesn't mean all argcc are argument of function in the target function we must check
        '''
        result=list()
        for i in range(0,len(self.project.factory.cc().ARG_REGS)): 
            tmp_ret=self._trackInputOfFuncionCall(vex,i,target_fAddr)
            if tmp_ret is not None :
                result.append(tmp_ret)
                # if len(result) == 0:
                #     result.append(tmp_ret)
                # else:
                #     flag=True
                #     for item in result:
                #         if (item[0] ==tmp_ret[0]) and (item[1].con.value == tmp_ret[1].con.value) and item[2] ==tmp_ret[2]:
                #             flag=False
                #             break
                #     if flag:
                #         result.append(tmp_ret)

        return result
    
            
    def mallocRetCopyToARGCC(self,vex,callee,caller):
        '''
        after getting argcc of callee we check and return argc who malloc return value is copied into.
        vex argument is vex block of where callee called(getBlockOFFunctionCall(callee))
        '''
        args_cc=self.getArgsCC(vex,self.getFuncAddress(callee))
        rax=self.getRetStoreLocOnStackOfFunction('malloc',caller)
        result=list()
        for i in rax:
            for addr,rx in i.items():
                for cc in args_cc:
                    if (rx[1].con.value == cc[1].con.value) and rx[2]==cc[2]:
                        result.append(cc)
                    
        return result
    
    def targetValueCopyToArgCC(self,vex,callee,value):
        """
            checks value is copied into argcc or not

        """
        args_cc=self.getArgsCC(vex,self.getFuncAddress(callee))
        for cc in args_cc:
            if (value[1].con.value == cc[1].con.value) and value[2]==cc[2]: 
                return cc


    
    def trackREGCCinCallee(self,caller,callee,callblock,targetRegCC=None):
        '''
            track if reg cc (that malloc return value is copy to it) store in zero block of callee
            return:
                ('rdi', <pyvex.expr.Const at 0x7f8a1c8f6a08>, 'Iop_Add64')
                where rdi is store in const location relative to rbp register in callee function
        '''
        result=list()
        if callblock  is  None:
            return resutl 
        
        if targetRegCC is None:
            r=self.mallocRetCopyToARGCC(callblock.vex,callee,caller)
        else:
            r=targetRegCC
            
        if len(r) == 0:
            return result
        
        regs=list()
        for i in r:
            regs.append(i[0])
        t=self.getBlockOfFunctionAt(callee,0)
        rbp_tmp=self.listOfWrTmpWithRegName(t.vex,'rbp')
        if len(rbp_tmp) == 0:
            return result
        else:
            rbp_tmp=rbp_tmp[0].tmp
        
        temps_get=list()
        for i in regs:
            tmp=self.listOfWrTmpWithRegName(t.vex,i)
            for item in tmp:
                temps_get.append('t'+str(item.tmp))
                temps_get.extend(self.listOfEffectedTempBy(t.vex,'t'+str(item.tmp)))
        
        for i in regs:
            stores=self.storeEffectedByReg(t.vex,i)
            for item in stores:
                if isinstance(item.data,pyvex.expr.RdTmp):
                    tmp_var='t'+str(item.data.tmp)
                    if tmp_var in temps_get:
                        if isinstance(item.addr,pyvex.expr.RdTmp):
                            addr_tmp_var='t'+str(item.addr.tmp)
                            target=self.targetWrTempByTempName(t.vex,addr_tmp_var)
                            if isinstance(target.data,pyvex.expr.Binop ) and 'Iop_Add' in target.data.op or 'Iop_Sub' in target.data.op:
                                effected_rbp=self.listOfEffectedTempBy(t.vex,'t'+str(rbp_tmp))
                                tmp_var='t'+str(target.data.args[0].tmp)
                                if (tmp_var in effected_rbp) or (tmp_var == 't'+str(rbp_tmp)):
                                    result.append((i,target.data.args[1],target.data.op))
        return result


    def _listOfStoreWithTempNameDst(self,vex,tmp_name):
        """
        returns Store(tmp_name)=someting
        """
        result=list()
        for i in self.getVexListCommand(vex,pyvex.IRStmt.Store):
            if isinstance(i.addr,pyvex.expr.RdTmp):
                if str(i.addr) == tmp_name:
                    result.append(i)
        
        return result
    
    
    def getAllCopiesSites(self,func_name,addr):
        '''
            if an address(malloc site) copied into another locations it resturns those locations
        '''
        result=[]
        check_list=[]
        check_list.append(addr)
        while len(check_list) > 0:
            addr=check_list.pop()
            tmp_res=self._getCopySites(func_name,addr)
            for item in tmp_res:
                result.append(item)
                if isinstance(item[1],int):
                    check_list.append(item[1])
                else:
                    check_list.append(item[1].con.value)
                
        return result
    
    def _getCopySites(self,func_name,addr):
        func=self.resolveAddrByFunction(self.getFuncAddress(func_name))
        result=[]
        for b in func.blocks:
            for wr_stmts in self.getVexListCommand(b.vex,pyvex.IRStmt.WrTmp):
                if isinstance(wr_stmts.data,pyvex.expr.Binop):
                    if isinstance(wr_stmts.data.args[1],pyvex.expr.Const) and wr_stmts.data.args[1].con.value == addr:
                        wr_tmp='t' + str(wr_stmts.tmp)
                        for load_stmt in self._listOfLoadwithTempNameSrc(b.vex,wr_tmp):
                            load_tmp='t'+str(load_stmt.tmp)
                            stores=self._listOfStoreWithTempNameSRC(b.vex,load_tmp)
                            if len(stores) > 0:
                                for store in stores:
                                    if isinstance(store.addr,pyvex.expr.RdTmp):
                                       sr_wr=self.targetWrTempByTempName(b.vex,str(store.addr))
                                       if isinstance(sr_wr.data,pyvex.expr.Binop) and isinstance(sr_wr.data.args[1],pyvex.expr.Const):
                                           result.append(('rbp:{}'.format('t'+str(sr_wr.tmp)),sr_wr.data.args[1],sr_wr.data.op))
                                       elif isinstance(sr_wr.data,pyvex.expr.Load) and isinstance(sr_wr.data.addr,pyvex.expr.RdTmp):
                                           ssr_wr=self.targetWrTempByTempName(b.vex,str(sr_wr.data.addr) )
                                           if isinstance(ssr_wr.data,pyvex.expr.Binop) and isinstance(ssr_wr.data.args[1],pyvex.expr.Const):
                                               result.append(('rbp:{}'.format('t'+str(ssr_wr.tmp)),ssr_wr.data.args[1],ssr_wr.data.op))
                                    elif  isinstance(store.addr,pyvex.expr.Const):
                                        result.append(('static',store.addr.con.value,self.getAddressStatement(b.vex,store)))
                            else:
                                for wrs in self.getVexListCommand(b.vex,pyvex.IRStmt.WrTmp):                    
                                    if isinstance(wrs.data,pyvex.expr.Binop) and isinstance(wrs.data.args[0],pyvex.expr.RdTmp) and str(wrs.data.args[0])==load_tmp:
                                        bio_tmp='t'+str(wrs.tmp)
                                        for st in self._listOfStoreWithTempNameSRC(b.vex,bio_tmp):
                                            if isinstance(st.addr,pyvex.expr.RdTmp):
                                                sr_wr=self.targetWrTempByTempName(b.vex,str(st.addr))
                                                if isinstance(sr_wr.data,pyvex.expr.Binop):
                                                    result.append(('rbp:{}'.format('t'+str(sr_wr.tmp)),sr_wr.data.args[1],sr_wr.data.op))
                elif  isinstance(wr_stmts.data,pyvex.expr.Load):   
                    if isinstance(wr_stmts.data.addr,pyvex.expr.Const) and wr_stmts.data.addr.con.value == addr:
                        load_tmp='t'+str(wr_stmts.tmp)
                        stores=self._listOfStoreWithTempNameSRC(b.vex,load_tmp)
                        for store in stores:
                            if isinstance(store.addr,pyvex.expr.RdTmp):
                               sr_wr=self.targetWrTempByTempName(b.vex,str(store.addr))
                               if isinstance(sr_wr.data,pyvex.expr.Binop) and isinstance(sr_wr.data.args[1],pyvex.expr.Const):
                                   result.append(('rbp:{}'.format('t'+str(sr_wr.tmp)),sr_wr.data.args[1],sr_wr.data.op))
                               elif isinstance(sr_wr.data,pyvex.expr.Load) and isinstance(sr_wr.data.addr,pyvex.expr.RdTmp):
                                   ssr_wr=self.targetWrTempByTempName(b.vex,str(sr_wr.data.addr) )
                                   if isinstance(ssr_wr.data,pyvex.expr.Binop) and isinstance(ssr_wr.data.args[1],pyvex.expr.Const):
                                       result.append(('rbp:{}'.format('t'+str(ssr_wr.tmp)),ssr_wr.data.args[1],ssr_wr.data.op))
                            elif  isinstance(store.addr,pyvex.expr.Const):
                                result.append(('static',store.addr.con.value,self.getAddressStatement(b.vex,store)))   
        return result
                
    def _listOfStoreWithTempNameSRC(self,vex,tmp_name):
        """
        returns Store(tmp_name)=someting
        """
        result=list()
        for i in self.getVexListCommand(vex,pyvex.IRStmt.Store):
            if isinstance(i.data,pyvex.expr.RdTmp):
                if str(i.data) == tmp_name:
                    result.append(i)
        
        return result
    
    def _listOfLoadwithTempNameSrc(self,vex,tmp_name):
        """
        returns someting=LDle:Isize(tmp_name)
        """
        result=list()
        for i in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(i.data,pyvex.expr.Load): 
                if isinstance(i.data.addr,pyvex.expr.RdTmp):
                    load_src_tmp='t'+str(i.data.addr.tmp)
                    if load_src_tmp == tmp_name:
                        result.append(i)
                    
        return result    
    
    #review
    def isWriteInAddrHeapRelativeWithRBP(self,vex,dst_addr):
        '''
        track is an write into location dest_addr relative with rbp in heap
        '''
        
        result=[]
        rbp_tmp=self.listOfWrTmpWithRegName(vex,'rbp')
        if len(rbp_tmp) == 0:
            return result
        else:
            rbp_tmp='t'+str(rbp_tmp[0].tmp)

        bios=list()
        for i in vex.statements:
            if isinstance(i,pyvex.IRStmt.WrTmp):
                if isinstance(i.data,pyvex.expr.Binop):
                    if 'Iop_Add' in i.data.op or 'Iop_Sub' in i.data.op :
                       bios.append(i)
        for bio in bios:
            if isinstance(bio.data.args[0],pyvex.expr.RdTmp) and isinstance(bio.data.args[1],pyvex.expr.Const):
                tmp='t'+str(bio.data.args[0].tmp)
                addr=bio.data.args[1].con.value
                if tmp == rbp_tmp and addr == dst_addr:
                    loads=self._listOfLoadwithTempNameSrc(vex,'t'+str(bio.tmp))
                    if len(loads) > 0:
                        for load in loads:
                            load_effected_list=self.listOfEffectedTmpWithTargetTemp(vex,'t'+str(load.tmp),consider_stores=False)
                            load_effected_list.append('t'+str(load.tmp))
                            stores=self.storeEffectedByReg(vex,'rbp')
                            
                            for store in stores:
                                if isinstance(store.addr,pyvex.expr.RdTmp):
                                    st_tmp='t'+str(store.addr.tmp)
                                    if st_tmp in load_effected_list:
                                        result.append(self.getAddressStatement(vex,store))
                                    else:
                                        target=self.targetWrTempByTempName(vex,st_tmp)
                                        if isinstance(target.data,pyvex.expr.Binop):
                                            if 'Iop_Add' in target.data.op:
                                                if isinstance(target.data.args[0],pyvex.expr.RdTmp):
                                                    if str(target.data.args[0]) in load_effected_list:
                                                        result.append(self.getAddressStatement(vex,store))
        return result
    
    def trackWriteIntoARGCCINCallee(self,callee,argcc):
        '''
        track in callee that is a store in register cc in argc
        argc=(reg_name,const,opr)
        
        Returns
        -------
            address of store and block of that store

        '''
        callee_func=self.resolveAddrByFunction(self.getFuncAddress(callee)) 
        result=list()
        for blck in callee_func.blocks:
            rbp_addr=argcc[1].con.value
            wr_addr=self.isWriteInAddrHeapRelativeWithRBP(blck.vex,rbp_addr)
            if len(wr_addr) > 0:
                for tmp_addr in wr_addr:
                    if tmp_addr not in  result:
                        result.append(tmp_addr)          
        return result
    
    
    def trackWritesIntoStaticVars(self,func_name,addr):
        target_func=self.resolveAddrByFunction(self.getFuncAddress(func_name)) 
        result=[]
        for b in target_func.blocks:
            for wr_stmts in self.getVexListCommand(b.vex,pyvex.IRStmt.WrTmp):
                if isinstance(wr_stmts.data,pyvex.expr.Load) and isinstance(wr_stmts.data.addr,pyvex.expr.Const) and wr_stmts.data.addr.con.value==addr:
                    stores=self._listOfStoreWithTempNameDst(b.vex,'t'+str(wr_stmts.tmp))
                    if len(stores)  > 0:
                        for store in stores:
                            result.append(self.getAddressStatement(b.vex,store))
                    else:
                        for bios in self.getVexListCommand(b.vex,pyvex.IRStmt.WrTmp):
                            if isinstance(bios.data,pyvex.expr.Binop) and isinstance(bios.data.args[0],pyvex.expr.RdTmp) and str(bios.data.args[0]) == 't'+str(wr_stmts.tmp):
                                for store in self._listOfStoreWithTempNameDst(b.vex,'t'+str(bios.tmp)):
                                    result.append(self.getAddressStatement(b.vex,store))
        return result    
            

    def getFunctionCalledBetweenBoundry(self,caller,start_addr,end_addr):
        '''
        return functions called between start address and end address in caller function
        '''
        caller=self.resolveAddrByFunction(self.getFuncAddress(caller)) 
        start_discover=False
        result=list()
        caller_blocks=list(caller.blocks)
        caller_blocks.sort(key=lambda b:b.addr)
        for i in caller_blocks:
            if ~start_discover:
                if start_addr in i.instruction_addrs:
                    start_discover=True
            if start_discover:
                if end_addr in i.instruction_addrs:
                    return result
                else:
                    if i.vex.jumpkind=='Ijk_Call':
                        jump=self._getCallPROPSFromCFG(i.addr)
                        if jump:
                            jmp_node,jmp_type=jump
                            if jmp_node.is_simprocedure and 'Unresolvable' in jmp_node.name:
                                addr=self._tryToResolveJump(caller.name,i.vex)
                                if addr:
                                    func=self.resolveAddrByFunction(addr)
                                    if func:
                                        result.append((addr,func.name))
                            else:
                                addr=jmp_node.addr
                                func=self.resolveAddrByFunction(addr)
                                if func:
                                    result.append((addr,func.name))
        return result
    
    def _tryToResolveJump(self,func_name,vex):
        stack={}
        for addr,value in self.getSimpleWrINStackFor(func_name):
            stack[addr]=value
        if len(stack) > 0:
            rbps=self._getRBPTemps(vex)
            if len(rbps) > 0:                        
                if isinstance(vex.next,pyvex.expr.RdTmp):
                    target_tmp=str(vex.next)
                    wr_target=self.targetWrTempByTempName(vex,target_tmp)
                    if isinstance(wr_target.data,pyvex.expr.Load) and isinstance(wr_target.data.addr,pyvex.expr.RdTmp):
                        addr_tmp=str(wr_target.data.addr)
                        addr_wr_target=self.targetWrTempByTempName(vex,addr_tmp)
                        if isinstance(addr_wr_target.data,pyvex.expr.Binop):
                            lhs,rhs=addr_wr_target.data.args
                            if isinstance(lhs,pyvex.expr.RdTmp) and isinstance(rhs,pyvex.expr.Const):
                                if str(lhs) in rbps:
                                    if rhs.con.value in stack.keys():
                                        addr=stack[rhs.con.value]
                                        if self.isFunctionAddr(addr):
                                            return addr
                        
            
    def remvoeSTLFunctionInList(self,func_list):
        '''
            remove simprocedure functions in above list
        '''
        remove_list=[]
        for j  in func_list:
            for i in angr.SIM_PROCEDURES.keys():
                if j[1]  in  angr.SIM_PROCEDURES[i].keys():
                    remove_list.append(j)

        for rm in remove_list:
            if rm in func_list:
                func_list.remove(rm)
               
        del(remove_list)
        return func_list
                
    
    def isWriteHappendInBoundry(self,caller,start_addr,end_addr,addr):
        '''
            determined is write heppened in this address between this boundry
        '''
        caller=self.resolveAddrByFunction(self.getFuncAddress(caller)) 
        start_discover=False
        end_discover=False
        result=list()
        for i in caller.blocks:
            if start_discover == False:
                if start_addr in i.instruction_addrs:
                    start_discover=True
            if start_discover:
                if end_addr in i.instruction_addrs:
                    end_discover=True
                    
                dst=self.isWriteInAddrHeapRelativeWithRBP(i.vex,addr)
                if len(dst) > 0:
                    for dst_addr in dst:
                        if dst_addr not in result:
                            result.append(dst_addr)
                
                if end_discover == True:
                    return result
        return result
                     
    def _isAddressLoadIntoReg(self,vex,addr,reg_offset):
        put=self._getLastPutStmtByOffset(vex,reg_offset)
        if put is None:
            return False
        
        for wr_stmts in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(wr_stmts.data,pyvex.expr.Load) and isinstance(wr_stmts.data.addr,pyvex.expr.Const) and wr_stmts.data.addr.con.value==addr:
                if isinstance(put.data,pyvex.expr.RdTmp) and str(put.data) == 't'+str(wr_stmts.tmp):
                    return True
        return False

        
    def  _mapAddrOfMallocInCallerAndCalle(self,callee,caller,reversed=None,whole=False):
        """
        maps relative address of malloc related to rbp in caller into calllee
        """
        if whole:
            result=list()
        else:
            result=dict()
        for callBlock in self.getBlockOFFuctionCall(callee,caller):
            for mr in self.mallocRetCopyToARGCC(callBlock.vex,callee,caller):
                for regcc in self.trackREGCCinCallee(caller,callee,callBlock):
                    if mr[0] == regcc[0]:
                        if whole:
                            result.append(regcc)
                        else:
                            if reversed is None:
                                result[mr[1].con.value]=regcc[1].con.value
                            else:
                                result[regcc[1].con.value]=mr[1].con.value
        return result
    
    def _mapRegccInCalleeAndCaller(self,caller,callee,caller_regcc):
        result=[]
        for callBlock in self.getBlockOFFuctionCall(callee,caller):
            input_callee=[]
            callee_argcc=self.getArgsCC(callBlock.vex,self.getFuncAddress(callee))
            for caller_arc in caller_regcc:
                for callee_arc in callee_argcc:
                    if caller_arc[1].con.value == callee_arc[1].con.value:
                        if callee_arc not in input_callee:
                            input_callee.append(callee_arc)
            map=self.trackREGCCinCallee(caller,callee,callBlock,targetRegCC=input_callee)
            result.append((callBlock.addr,map))
        return result
    
    
    def _isFixedIndexAccess(self,func_name,wr_addr,vex,stack_vals=None):
        index=None
        rbps=self._getRBPTemps(vex)
                    
        store=self.getStoreInTargetAddr(wr_addr,vex)
        if isinstance(store.data,pyvex.expr.Const):
            if isinstance(store.addr,pyvex.expr.RdTmp):
                target_wr=self.targetWrTempByTempName(vex,str(store.addr))
                if target_wr and isinstance(target_wr.data,pyvex.expr.Binop):
                    arg1,arg2=target_wr.data.args
                    if isinstance(arg2,pyvex.expr.Const):
                        index=arg2.con.value
                    else:
                        maps=self.getFixTemps(func_name,vex,rbps,wr_stacks=stack_vals)
                        tmp_target=self.targetWrTempByTempName(vex,str(arg2))
                        if isinstance(tmp_target.data,pyvex.expr.Binop):
                            t_arg1,t_arg2=tmp_target.data.args
                            if isinstance(t_arg1,pyvex.expr.RdTmp) and isinstance(t_arg2,pyvex.expr.Const):
                                se_map=self._searchInMap(maps,str(t_arg1))
                                if se_map and 'Iop_Shl' in tmp_target.data.op :
                                    index=bino(tmp_target.data.op,se_map,t_arg2.con.value)                               
        return index

    def getFixTemps(self,func_name,vex,rbps,wr_stacks=None):
        maps={}
        search_list=[]
        wr_into_stack=None
        if wr_stacks:
            wr_into_stack=wr_stacks
        else: 
            wr_into_stack=self.getSimpleWrINStackFor(func_name)
        for i in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
            if isinstance(i.data,pyvex.expr.Binop):
                if isinstance(i.data.args[0],pyvex.expr.RdTmp) and str(i.data.args[0]) in rbps:
                    if isinstance(i.data.args[1],pyvex.expr.Const):
                        for addr,value in wr_into_stack:
                            bio_addr=i.data.args[1].con.value
                            if addr == bio_addr:
                                bio_tmp='t'+str(i.tmp)
                                for load in self._listOfLoadwithTempNameSrc(vex,bio_tmp):
                                    target_tmp='t'+str(load.tmp)
                                    value=int(numpy.int32(value))
                                    if value not in maps.keys():
                                        maps[value]=set()
                                        maps[value].add(target_tmp)
                                        search_list.append(target_tmp)
                                    else:
                                        maps[value].add(target_tmp)
                                        search_list.append(target_tmp)
        while len(search_list):
            tmp=search_list.pop()
            for ef_tmp in self.listOfEffectedTmpWithTargetTemp(vex,tmp):
                wr_t=self.targetWrTempByTempName(vex,ef_tmp)
                if isinstance(wr_t,pyvex.IRStmt.WrTmp) and isinstance(wr_t.data,pyvex.expr.Unop):
                    value=self._searchInMap(maps,tmp)
                    val=intWiden(wr_t.data.op,value)    
                    if val:
                        tmp_name='t'+str(wr_t.tmp)
                        if val not in maps.keys():
                            maps[val]=set()
                        maps.get(val).add(tmp_name)
                        search_list.append(tmp_name)
        return maps
    
    
    def getMallocSize(self,vex,func_name='main'):
        """
            if malloc size is static it returns it's size
        """
        regcc=self.project.factory.cc().ARG_REGS[0]
        put=self._getLastPutStmtByOffset(vex,self.getRegOffset(vex,regcc))
        if put and isinstance(put.data,pyvex.expr.Const):
            return put.data.con.value
            
        rbps=self._getRBPTemps(vex)
        result=[]
        if len(rbps) > 0:                
            maps=self.getFixTemps(func_name,vex,rbps)
                               
            put=self._getLastPutStmtByOffset(vex,self.getRegOffset(vex,regcc))
            if put and isinstance(put.data,pyvex.expr.RdTmp):
                ptmp=str(put.data)
                search_res=self._searchInMap(maps,ptmp)
                if search_res:
                    return search_res
                else:
                    for i in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                        if isinstance(i.data,pyvex.expr.Binop):
                            arg1,arg2=i.data.args
                            if isinstance(arg1,pyvex.expr.RdTmp) and isinstance(arg2,pyvex.expr.Const):
                                val=self._searchInMap(maps,str(arg1))
                                if val:
                                    new_val=bino(i.data.op,val,arg2.con.value)
                                    if new_val:
                                        if new_val in maps.keys():
                                            maps[new_val].add('t'+str(i.tmp))
                                        else:
                                            maps[new_val]=set()
                                            maps[new_val].add('t'+str(i.tmp))
                    
                    
                    for i in self.getVexListCommand(vex,pyvex.IRStmt.WrTmp):
                        if isinstance(i.data,pyvex.expr.Binop):
                            arg1,arg2=i.data.args
                            if isinstance(arg1,pyvex.expr.RdTmp) and isinstance(arg2,pyvex.expr.RdTmp):
                                val1=self._searchInMap(maps,str(arg1))
                                val2=self._searchInMap(maps,str(arg2))
                                if val1 and val2:
                                    new_val=bino(i.data.op,val1,val2)
                                    if new_val:
                                        if new_val in maps.keys():
                                            maps[new_val].add('t'+str(i.tmp))
                                        else:
                                            maps[new_val]=set()
                                            maps[new_val].add('t'+str(i.tmp))
                                        
                                        
                    val=self._searchInMap(maps,ptmp)
                    if val:
                        return val
                    else:
                        put_wr=self.targetWrTempByTempName(vex,ptmp)
                        if isinstance(put_wr.data,pyvex.expr.Binop):
                            arg1,arg2=put_wr.data.args
                            if isinstance(arg1,pyvex.expr.RdTmp) and isinstance(arg2,pyvex.expr.RdTmp):
                                val1=self._searchInMap(maps,str(arg1))
                                val2=self._searchInMap(maps,str(arg2))
                                if val1 and val2:
                                    return bino(put_wr.data.op,val1,val2)
                            elif isinstance(arg1,pyvex.expr.RdTmp) and isinstance(arg2,pyvex.expr.Const):
                                val=self._searchInMap(maps,str(arg1))
                                if val:
                                    return bino(put_wr.data.op,val,arg2.con.value)
    
    def _searchInMap(self,maps,tmp):
        for value,tmps in maps.items():
            if tmp in tmps:
                return value
        
        
    def _getFixArgcOnStack(self,caller,callee):
        stack={}
        new_stack={}
        for addr ,value in self.getSimpleWrINStackFor(caller):
            stack[addr]=value
        for  block in self.getBlockOFFuctionCall(callee,caller):
            addr=self.getFuncAddress(callee)
            target_argc=[]
            for argc in self.getArgsCC(block.vex,addr):
                for s_addr,s_value in stack.items():
                    if argc[1].con.value == s_addr or argc[2] == 'Iex_Const':
                        target_argc.append(argc)
            for argc in target_argc:
                 map_regc=self._mapRegccInCalleeAndCaller(caller,callee,[argc])
                 for addr,props in map_regc:
                     if len(props) > 0:
                         if argc[2] == 'Iex_Const':
                             new_stack[props[0][1].con.value]=argc[1].con.value 
                         else:
                             new_stack[props[0][1].con.value]=stack[argc[1].con.value]
        return new_stack        
            
    def getSimpleWrINStackFor(self,func_name,with_addr=False,block=None):
        func=self.resolveAddrByFunction(self.getFuncAddress(func_name))
        blocks=[]
        if block:
            blocks.append(block)
        else:
            blocks=func.blocks
        result=[]
        for blck in blocks:
            value=[]
            addrs=[]
            items=self._getWritesInStack(blck.vex)
            while len(items) > 0:
                item=items.pop()
                if item[0] not in addrs:
                    value.append((blck.addr,item))
                    addrs.append(item[0])
            result.extend(value)
        b_list={}
        tmp_res={}
        for addr ,props in result:
            key=props[0]
            if key not in b_list.keys() or b_list[key] <addr:
                b_list[key]=addr
                if with_addr:
                    tmp_res[key]=(addr,props) 
                else:
                    tmp_res[key]=props

        return list(tmp_res.values())
    
    def _getWritesInStack(self,vex):
        rbp_tmp=self.listOfWrTmpWithRegName(vex,'rbp')
        result=[]
        rbps=self._getRBPTemps(vex)
        for i in self.getVexListCommand(vex,pyvex.IRStmt.Store):
            if isinstance(i.data,pyvex.expr.Const) and isinstance(i.addr,pyvex.expr.RdTmp):
                src_tmp=str(i.addr)
                wr_target=self.targetWrTempByTempName(vex,src_tmp)
                if isinstance(wr_target,pyvex.stmt.WrTmp) and isinstance(wr_target.data,pyvex.expr.Binop):
                    lhs=wr_target.data.args[0]
                    rhs=wr_target.data.args[1]
                    if isinstance(lhs,pyvex.expr.RdTmp):
                        rbp_put=self._getLastPutStmtByOffset(vex,self.getRegOffset(vex,'rbp'))
                        if rbp_put is not None:
                            if self.getAddressStatement(vex,rbp_put) < self.getAddressStatement(vex,wr_target):
                                if isinstance(rbp_put.data,pyvex.expr.RdTmp):
                                    tmp_put=str(rbp_put.data)
                                    if (str(lhs) == tmp_put) or (str(lhs) in rbps):
                                        val=i.data.con.value
                                        if val in range(self.project.loader.min_addr,self.project.loader.max_addr):
                                            if self.isFunctionAddr(val)==False:
                                                str_len=self._est_str_length(val)
                                                val=self.project.loader.memory.load(val,str_len)
                                        result.append( (rhs.con.value,val))
                        elif str(lhs) in rbps:
                            val=i.data.con.value
                            if val in range(self.project.loader.min_addr,self.project.loader.max_addr):
                                if self.isFunctionAddr(val)==False:
                                    str_len=self._est_str_length(val)
                                    val=self.project.loader.memory.load(val,str_len)
                            result.append( (rhs.con.value,val))
        return result

    
    def _est_str_length(self,addr):
        length=1
        while True:
            if self.project.loader.memory.load(addr,length)[-1] is 0:
                break
            length=length+1
        return length
    
    def isFuncCallAt(self,block,func_name):
        '''
            checks that target function is called in the specified block

        '''
        addr=0
        if block.vex.jumpkind == 'Ijk_Call':
            addr=list(block.vex.constant_jump_targets)[0]
            
        return addr == self.getFuncAddress(func_name)
    
    
    ## maping
    def _getScanfSite(self,b,current_inp):
        maps={}
        put=self._getLastPutStmtByOffset(b.vex,self.getRegOffset(b.vex,self.project.factory.cc().ARG_REGS[0]))
        if put and isinstance(put.data,pyvex.expr.Const):
            addr=put.data.con.value
            ptr_len=self._est_str_length(addr)
            ptr=self.project.loader.memory.load(addr,ptr_len)
            numbs_input=ptr.count(b"%")
        
        
        for inp_index in range(numbs_input):
            maps[current_inp]=self._findARGPos(b,inp_index+1)
            current_inp+=1
        return maps
    
    
    def _findARGPos(self,b,inp_index):
        put=self._getLastPutStmtByOffset(b.vex,self.getRegOffset(b.vex,self.project.factory.cc().ARG_REGS[inp_index])) 
        if isinstance(put.data,pyvex.IRExpr.RdTmp):
            src_tmp=str(put.data)
            target=self.targetWrTempByTempName(b.vex,src_tmp)
            if isinstance(target.data,pyvex.expr.Load) and isinstance(target.data.addr,pyvex.IRExpr.RdTmp):
                src_tmp=self.targetWrTempByTempName(b.vex,str(target.data.addr))
                if isinstance(src_tmp.data,pyvex.expr.Binop) and isinstance(src_tmp.data.args[1],pyvex.expr.Const) :
                    addrss=[src_tmp.data.args[1].con.value]
                    for items in self.getAllCopiesSites('main',src_tmp.data.args[1].con.value):
                        addrss.append(items[1].con.value)
                    return (addrss,'HEAP')
            elif isinstance(target.data,pyvex.expr.Binop) and isinstance(target.data.args[1],pyvex.expr.Const):
                addrss=[target.data.args[1].con.value]
                for items in self.getAllCopiesSites('main',target.data.args[1].con.value):
                    addrss.append(items[1].con.value)
                return (addrss,'STACK') 
    
    def _getInputMaps(self):
        maps={}
        last_index=0
        main_blocks=list(self.resolveAddrByFunction(self.getFuncAddress('main')).blocks)
        for block in main_blocks:
            keys=list(maps.keys())
            last_index= max(keys)+1 if len(keys) > 0 else 0 
            if block.vex.jumpkind == 'Ijk_Call':
                if 'scanf' in self.resolveAddrByFunction(block.vex.next.con.value).name:
                    res=self._getScanfSite(block,last_index)
                    if res:
                        maps={**res,**maps}
                elif 'gets' in self.resolveAddrByFunction(block.vex.next.con.value).name:
                    maps[last_index]=self._findARGPos(block,0)
        return maps

    def trackInputsInEntryPoint(self,arg_index):
        '''
        it track inputs address :
            sample output:
            {0x0: ([0xffffffffffffff60], 'argv'),
             0x1: ([0xffffffffffffff80, 0xffffffffffffff88], 'HEAP'),
             0x2: ([0xffffffffffffff7c], 'STACK'),
             0x3: ([0xffffffffffffff7b], 'STACK'),
             0x4: ([0xffffffffffffff90], 'STACK')}

        '''
        input_maps=self._getInputMaps()
        maps={}
        argv_pos={}
        ap=1
        length=len(arg_index) + len(input_maps)
        for item in range(length):
            if item in arg_index:
                maps[item]=([self.getArgvAddrsOnStack()[1].con.value],'argv')
                argv_pos[ap]=item
                ap+=1
            else:
                min_key=min(input_maps.keys())
                maps[item]=input_maps.pop(min_key)
        return (maps,argv_pos)

    
    def trackCalleeArgsInMain(self,callee,b,argv_pos,maps):
        '''
       this function returns a map that specify which input is given in callee in main 
        '''
        func_map={}

        argcc=self.getArgsCC(b.vex,self.getFuncAddress(callee))
        maps_argc=self._mapRegccInCalleeAndCaller('main',callee,argcc)
        if len(maps_argc)> 0 and len(maps_argc[0][1])>0:
            arg_len=len(maps_argc[0][1])
        else:
            raise Exception('this function does not have arguments')
        argv_map=self.checkForArgvAsArgument(callee)
        for arg_indx in range(arg_len):
            target_reg=self.project.factory.cc().ARG_REGS[arg_indx]
            for argc in argcc:
                if argc[0] == target_reg:
                    addr=argc[1].con.value
                    arg_pos=self._searchINArgMaps(maps,addr)
                    if arg_pos is not None: 
                        if maps[arg_pos][1]=='argv' :
                            if len(argv_map) > 0 :
                                argv_index=self._searchINArgVMaps(argv_map,target_reg)
                                if argv_index:
                                    func_map[arg_indx]=argv_pos[argv_index]
                                    break
                        else:
                            func_map[arg_indx]=arg_pos
                            break
        return func_map

    

    def _searchINArgVMaps(self,maps,reg):
        '''
            it search in argv maps returned from checkForArgvAsArgument
        '''
        arg_number=[]
        for addr ,items in  maps.items():
            for argv_num,reg_name in items:
                if reg_name == reg:
                    return argv_num



    def _searchINArgMaps(self,maps,addr):
        '''
        it search in maps returned from trackInputsInEntryPoint
        '''
        for numb ,items in  maps.items():
            if addr in items[0]:
                return numb
            
    def getMapOFArguments(self,args_index,target):
        res_map={}
        chain=self.getCallChain(target)[0].split('-')
        callee=chain[1]
        b=self.getBlockOFFuctionCall(callee,'main')[0] 
        entry_map,argv_pos=self.trackInputsInEntryPoint(args_index)
        res_map[callee]={**self.trackCalleeArgsInMain(callee,b,argv_pos,entry_map)}
        
        for chain_indx in range(len(chain)-2):
            caller=chain[chain_indx]
            callee=chain[chain_indx+1]
            tmp_map={}
            b=self.getBlockOFFuctionCall(callee,caller)[0]
            argcc=self.getArgsCC(b.vex,self.getFuncAddress(callee))
            maps_argc=self._mapRegccInCalleeAndCaller(caller,callee,argcc)
            for addr,props in maps_argc:
                for reg,addr,op in props:
                    index=self.project.factory.cc().ARG_REGS.index(reg)
                    tmp_map[index]=[addr.con.value]
                    for item in self.getAllCopiesSites(callee,addr.con.value):
                        tmp_map[index].append(item[1].con.value)
            b=self.getBlockOFFuctionCall(chain[chain_indx+2],callee)[0]
            argcc=self.getArgsCC(b.vex,self.getFuncAddress(chain[chain_indx+2]))
            maps_argc=self._mapRegccInCalleeAndCaller(chain[chain_indx+1],chain[chain_indx+2],argcc)
            arg_len=len(maps_argc[0][1])
            res_map[chain[chain_indx+2]]={}
            for indx in range(arg_len):
                for reg,argcc_addr,op in argcc:
                    if self.project.factory.cc().ARG_REGS[indx] == reg:
                        for arg_index,address in tmp_map.items():
                            if argcc_addr.con.value in address:
                                res_map[chain[chain_indx+2]][self.project.factory.cc().ARG_REGS.index(reg)]=arg_index
        final_map=res_map[target]
        chain.pop(0)
        chain.pop(-1)
        chain.reverse()
        for func in chain:
            for arg_number,idx in final_map.items():
                final_map[arg_number]=res_map[func][idx]
        return final_map
