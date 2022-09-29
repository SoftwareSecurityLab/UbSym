#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 28 19:22:26 2020

@author: Sara Baradaran, Mahdi Heidari, Ali Kamali
"""


import subprocess,re,itertools
import numpy as np

def runTAR3(I,V,VV,VVV,inode,smooth=False,vv=None):
    NODE_PATH='./.node-{0}.txt'.format(inode)
    RUN_DIR='./analysis/tar3/sample/'
    lines=[]
    num_vars=len(V[0]) 
    if num_vars == 0:
        return None
    for item in V:
        if item in VV:
            item.append('good')
        elif item in VVV:
            item.append('bad')
        lines.append(list(map(str,item)))
            
    with open('./analysis/tar3/sample/data.data','w+') as handler:
        for line in lines:
            handler.write(','.join(line) + '\n')
        
    cp=subprocess.run(["../source/tar3/tar3", "data"],universal_newlines=True, stdout=subprocess.PIPE, cwd=RUN_DIR)
    

    lines=cp.stdout.split('\n')
    res=[]
    for x in lines:
        if re.search('^\d worth=.*',x.lstrip()) is not None:
            res.append(x.strip())
    
    if len(res) > 0:   
        with open(NODE_PATH,'w+') as handler:      
            for item in res:
                handler.write(item + '\n')
        
        if smooth:
            var_names=_seperateValues(res.copy(),only_names=True)
            vals=_seperateValues(res.copy())
            c_VV,c_vv=_correctInputs(vals, VV, vv)
            final_res=[]

            for i in var_names:
                idx=int(i.split('_')[1]) -1
                xdata=(np.array(c_VV)[:,idx]).copy()
                ydata=(np.array(c_vv)[:,idx]).copy()
                
                points_data=np.array(_sortPoints(xdata,ydata))

                
                islip=isLipschitz(points_data, 20) 
                if islip:
                    r=tuple(('{}'.format(i),points_data[:,0],points_data[:,1]))
                    final_res.append(r)
                else:
                    r=tuple(('{}'.format(i),None,None))
                    final_res.append(r)
            return final_res
            
    elif len(res) == 0:
        with open(NODE_PATH,'w+') as handler: 
            error='Error: no cdf value found!'
            if error in lines:
                handler.write("No CDF.")
            else:
                goodPart=None
                for line in lines:
                    c=line.strip()
                    if re.search('good:.*',c) is not None:
                        goodPart=c
                
                if goodPart is None:
                    handler.write('No Value')
                else:
                    goodPart=goodPart.split('[')[1]
                    goodPart=goodPart.replace(']','').split('-')[1]
                    goodPart=goodPart.replace('%','')
                    goodPart=int(goodPart)
                    if goodPart > 70:
                        handler.write("R")
                    else :
                        handler.write('No Value')
                
            if smooth: 
                final_res=[]
                for i in range(num_vars):
                    xdata=(np.array(VV)[:,i]).copy()
                    ydata=(np.array(vv)[:,i]).copy()
                    
                    points_data=np.array(_sortPoints(xdata,ydata))
                    
                    islip=isLipschitz(points_data, 20) 
                    if islip:
                        r=tuple(('var_{}'.format(i+1),points_data[:,0],points_data[:,1]))
                        final_res.append(r)
                    else:
                        r=tuple(('var_{}'.format(i+1),None,None))
                        final_res.append(r)
                return final_res
                
           
def _correctInputs(vals,system_in,unit_in):
    sinputs=[]
    uinputs=[]
    for val in vals:
        indx=[]
        bounds=[]
        for var_name,bnd in val:
            indx.append(int(var_name.split('_')[1])-1)
            bounds.append((float(bnd[0]),float(bnd[1])))
            
        for inp_indx in range(len(system_in)):
            sys_inp=system_in[inp_indx]
            unit_inp=unit_in[inp_indx]
            flag=False
            for i in range(len(indx)):
                if sys_inp[indx[i]] >= bounds[i][0] and sys_inp[indx[i]] <= bounds[i][1]:
                    flag=True
                else:
                    flag=False
                    break
            if flag == True:
                sinputs.append(sys_inp)
                uinputs.append(unit_inp)
    return (sinputs,uinputs)

def _sortPoints(xdata,ydata):
    data=[]
    for i in range(0,len(xdata)):
        data.append([xdata[i],ydata[i]])
        
    _data=[]
    for i in data:
        if i not in _data:
            _data.append(i.copy())
    del(data)
    _data.sort(key=lambda t: t[0]) 
    
    return _data
    
def isLipschitz(datas,k):
   
    dx = np.diff(np.array(datas)[:,0])
    
    #extra condition bcz any does not act correctly
    if (np.any(dx)<=0) or ( 0 in dx):
        return False
    
    points=list(itertools.combinations(datas, 2))
    max=None
    for point1,point2 in points:
        x1,y1=point1
        x2,y2=point2
        if x1==x2 and y1==y2:
            continue
        s=abs(x1-x2)
        r=abs(y1-y2)
        if r == 0:
            return False

        t=s/r
        if max is  None:
            max=t
        if t > max:
            max=t
    return max<k


def _seperateValues(res,only_names=False):
    var=[]
    if len(res) > 0:
        for t in res:
            t=t.replace(')','')
            t=t.split('\t')[1]
            t=t.replace('[','')
            items=t.split(' ')
            list_var=[]
            for item in items:
                name=item.split('=')[0]
                item=item.split('=')[1]
                item=item.replace(']', '')
                if only_names:
                    if name not in var:
                        var.append(name)
                else:
                    bnds=item.split('..')
                    bnds[0]=bnds[0].strip()
                    bnds[1]=bnds[1].strip() 
                    list_var.append((name,bnds))
            if only_names == False:
                var.append(list_var)
    return var


def getPosOnConfigFile(self,config_file='./analysis/tar3/sample/data.names'):
    handler=open(config_file,'r+')
    lines=handler.readlines()
    handler.close()
    
    change_idx=0;now_idx=0;attr_idx=0;indx=0;now_visitted=False;change_visitted=False
    for line in lines:
        if 'NOW' in line:
            now_visitted=True
            attr_idx=indx-1
            while True:
                if lines[attr_idx-1 ] != '\n':
                    break
                attr_idx=attr_idx-1
    
            indx=indx+1
            continue
        if now_visitted == True and line == '\n':
            now_idx=indx
            indx=indx+1
            now_visitted=False
            continue
        
        if 'CHANGES' in line:
            change_visitted=True
            indx=indx+1
            continue
        if change_visitted and line =='\n':
            change_idx=indx
            break
        
        indx = indx + 1
    return (attr_idx,now_idx,change_idx)


def generateTar3ConfingFile(arg_status,interest_indexes,config_file='./analysis/tar3/sample/data.names'):
    '''
    this function build tar3 data.names file based on unit arg status and intersting index on char stars in unit
    '''
    wrlist=[]
    wrlist.extend(['|Class:\n','bad,good\n', '\n', '|Attributes :  4\n'])
    nowlist=[ 'NOW\n']
    changelist=[ 'CHANGES\n']
    current_indx=1
    maps={}
    for indx,tp in arg_status.items():
        if tp != 'charPointer':
            var_name='var_{}'.format(current_indx)
            wrlist.append(var_name + ':continuous\n')
            nowlist.append(var_name + ':true\n')
            changelist.append(var_name + ':true\n')
            current_indx=current_indx+1
        else:
            for var_ind,pos in interest_indexes:
                if int(var_ind.split('_')[1]) == indx:
                    var_name='var_{}'.format(current_indx)
                    wrlist.append(var_name + ':continuous\n')
                    nowlist.append(var_name + ':[32;126]\n')
                    changelist.append(var_name + ':true\n')
                    current_indx=current_indx+1
                    if indx in maps.keys():
                        maps[indx].append((var_name,pos))
                    else:
                        maps[indx]=[(var_name,pos)]

    
    scorelist=[ 'SCORE\n', '4,8\n']
    wrlist.append('\n')
    nowlist.append('\n')
    changelist.append('\n')
    wrlist.extend(nowlist)
    wrlist.extend(changelist)
    wrlist.extend(scorelist)
    file=open(config_file,'w+')
    file.writelines(wrlist)
    file.close()
    if len(nowlist) == 2:
        return None
    return maps

    
