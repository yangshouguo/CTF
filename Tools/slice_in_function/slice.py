# coding=utf-8
import idaapi
import time
import idautils
from idc import *
import logging
import Queue
logger = logging.getLogger("slice")
logger.setLevel(logging.INFO)
logger.addHandler(logging.FileHandler("ida_slice.log"))
logger.info("Script run at %s" % time.asctime())
if idaapi.IDA_SDK_VERSION >= 700:
    import ida_idaapi
    import ida_kernwin
    from idaapi import *
    from idc import *

def wait_for_analysis_to_finish():
	'''
	等待ida将二进制文件分析完毕再执行其他操作
	'''
	print('[+] waiting for analysis to finish...')
	idaapi.autoWait()
	idc.Wait()
	print('[+] analysis finished')
wait_for_analysis_to_finish()


def get_addr_by_name(function_name):
    '''
    返回函数的地址
    function_name: 函数名
    '''
    for addr, name in Names():
        if name == function_name:
            return addr

# TODO: 获取目标函数地址
if len(idc.ARGV) >= 2:
    logger.info("idc.ARGV : %s" % str(idc.ARGV))
    function_name = idc.ARGV[1]
    addr = get_addr_by_name(function_name)
else:
    logger.info('No function_name specified')
    addr = ScreenEA() #在IDA中显示函数的地址


def Get_function_CFG(func_addr):
    '''
    得到函数的控制流图
    :param func_addr:int: 函数首地址
    :return: list(BasicBlock):返回函数中所有的基本块列表
    '''
    return list(idaapi.FlowChart(idaapi.get_func(func_addr)))

# : 定位目标代码 call reg
def search_call_register(start_addr):
    '''
    搜索 call reg; 指令， 例如 call eax; call [eax+8]; 等用寄存器定位跳转目标的指令
    '''
    target_list = []
    CALL_INSTRUCTION = ['call']
    for addr in FuncItems(start_addr):
        if GetMnem(addr) in CALL_INSTRUCTION:
            if GetOpType(addr, 0) in [o_reg, o_mem, o_displ]:
                target_list.append(addr)

    return target_list

LAST_REGISTER_DEPENDENCE={'mov':1,'lea':1,'call':0,'inc':0,'dec':0,'not':0
                         }#'只数据依赖最后一个操作数指令'
TWO_REGISTER_DEPENDENCE = ['sub','add','test','cmp','xchg','adc','nec','mul','div',
                           'and','or','xor','shl','sal','shr','sar'] #'依赖两个操作数的指令'

# ddg = {node_addr:{ depend_nodes:[]}}
# TODO: 建立函数的数据依赖图和控制依赖图
def ddg(cfg):
    '''
    根据cfg构建数据依赖图
    :param cfg: list: 控制流图
    :return: 数据依赖图  图中每个节点属性  node['addr']:int: 表示指令地址; node['depend']:list:表示数据依赖于该list中的指令
    '''
    def get_dd_addr(EA, block, endEA=-1, reg_name = ''):
        '''
        #TODO 得到指令 EA ，在block中的数据依赖指令; 只跟踪寄存器
        :param EA: int : 指令所在地址
        :param endEA: block分析结束指令地址
        :param block: BasicBlock: 基本块结构体
        :return : list: 返回依赖的指令地址,没找到返回None
        '''

        if endEA == -1:
            endEA = block.endEA
        # 获得当前指令依赖的寄存器
        if len(reg_name) > 0:
            return get_dd_addr(reg_name)


        Mnem = GetMnem(EA)
        if Mnem in LAST_REGISTER_DEPENDENCE.keys():
            order = LAST_REGISTER_DEPENDENCE[Mnem]
            reg_name = GetOpnd(EA, order)
            return get_reg_depend(reg_name)
        elif Mnem in TWO_REGISTER_DEPENDENCE:
            reg_name = GetOpnd(EA,0)
            dp1 = get_reg_depend(reg_name)
            reg_name = GetOpnd(EA,1)
            dp2 = get_reg_depend(reg_name)
            # TODO: 一条指令对两个寄存器都有依赖如何解决？
            
        def get_reg_depend(reg_name):
            # 寻找依赖指令
            curEA = endEA
            while curEA >= block.startEA:
                if reg_name == GetOpnd(curEA, 0):
                    return curEA
                curEA = PrevHead(curEA, block.startEA)
            return None
    ddgs = []

    for i in range(len(cfg)-1,-1,-1):
        bblock = cfg[i] # BasicBlock
        # 自下而上构建
        curEA = bblock.endEA
        while curEA >= bblock.startEA:
            visited_blocks = []
            iddg = {}
            iddg[curEA] = {}
            iddg[curEA]['depend_nodes'] = []
            logger.info("[r] searching for addr %s" % hex(curEA))
            # 当前基本块寻找数据依赖
            depended_addr = get_dd_addr(curEA, bblock, endEA=curEA)
            visited_blocks.append(bblock.startEA)
            if depended_addr != -1:# 当前基本块存在数据依赖
                iddg[curEA]['depend_nodes'].append(depended_addr)
            else:# 父节点寻找数据依赖
                q = Queue.Queue()
                for pblock in bblock.preds():
                    q.put(pblock)
                while not q.empty():
                    qblock = q.get()
                    if qblock.startEA in visited_blocks:
                        continue
                    depended_addr = get_dd_addr(curEA, qblock)
                    visited_blocks.append(qblock.startEA)
                    if depended_addr != -1:
                        iddg[curEA]['depend_nodes'].append(depended_addr)
                    else:
                        for qqblock in qblock.preds():
                            q.put(qqblock)
            ddgs.append(iddg)
            curEA = PrevHead(curEA, bblock.startEA)
        


# TODO: 根据目标代码, 利用基于图可达性的切片算法进行切片
    

# TODO: 输出从函数入口地址到目标代码的可能路径地址。


def main():
    print(hex(addr))
    list = search_call_register(addr)
    print(list)
    cfg_list = Get_function_CFG(addr)
    func_ddg = ddg(cfg_list)


    idc.Exit(0)
main()
