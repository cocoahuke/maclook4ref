//
//  main.m
//  mac_lookforAnyRef
//
//  Created by huke on 8/22/16.
//  Copyright (c) 2016 com.cocoahuke. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "capstone/capstone.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <mach-o/nlist.h>

const char* PATH = NULL;

uint32_t SEARCH_OFFSET = 0;
//查找用的偏移地址

#define Color_mark_ENABLE 1
//开启输出的颜色标示

#define List_INSTRUCTION 6
//需要为偶数, 指定多少行的汇编作为结果输出

int Print_ALLFUNC_OFFSET = 0;
//print all vtable offset, its super slow down the speed
//and if [?]], its mean the class is not defined in this kext. (In other kext)

int Advance_SEARCH_MODE = 0;
//会开启几项分析,然后搜索特定的引用,会使运行速度降低

int Advance_SEARCH_INDEX = 0 ;
//决定具体分析第几项内容


#pragma mark class_infoDic
NSMutableDictionary *class_infoDic = NULL; //全局类信息
/*
 class_infoDic包含arr
 arr[0] = class_size
 arr[1] = class_vtable
 arr[2] = class_vtableEnd
 */

#define COLOR_OFF	"\x1B[0m"
#define COLOR_WHITE	"\x1B[0;37m"
#define COLOR_RED	"\x1B[0;91m"
#define COLOR_GREEN	"\x1B[0;92m"
#define COLOR_YELLOW	"\x1B[0;93m"
#define COLOR_BLUE	"\x1B[0;94m"
#define COLOR_MAGENTA	"\x1B[0;95m"
#define COLOR_BOLDGRAY	"\x1B[1;30m"
#define COLOR_BOLDWHITE	"\x1B[1;37m"


NSMutableDictionary *all_symbol = NULL;

uint64_t rax;
uint64_t rbx;
uint64_t rcx;
uint64_t rdx;
uint64_t rdi;
uint64_t rsi;
uint64_t rbp;
uint64_t rsp;
uint64_t r8;
uint64_t r9;
uint64_t r10;
uint64_t r11;
uint64_t r12;
uint64_t r13;
uint64_t r14;
uint64_t r15;
uint64_t rip;

uint64_t modInitVM;
uint64_t modInitFileoff;
uint64_t modInitSize;

void get_allFunc(void *firstPage);

//machoH、文件相关函数
uint64_t machoGetVMAddr(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t machoGetFileAddr(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t machoGetSize(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t FilegetSize(char *file_path);

//分析每个内核扩展中的ModInit函数,主要的分析汇编代码的函数
void AnalysisModInitOfKEXT(void *bin);

//对类的vtable查找特定函数偏移
uint32_t lookforClass_offsetOfFunc(void *bin,uint64_t vtable_vm,uint64_t vtableEnd_vm,uint64_t func_vm); //New

int64_t getMEMOPoffset(csh handle,const cs_insn *insn); //得到lea指令的内存偏移数
int getMEMOPregister(csh handle,const cs_insn *insn); //得到lea指令的偏移寄存器

int getFirstReg(csh handle,const cs_insn *insn); //得到第一个寄存器
int getSecondReg(csh handle,const cs_insn *insn); //得到第二个寄存器

void* getMemFromAddrOfVM(void* bin,uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr);//转换汇编的虚拟内存地址,返回在内存中的实际内容

uint64_t getfileoffFromAddrOfVM(uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr);//转换虚拟内存地址,返回文件中偏移地址

uint64_t* getActualVarFromRegName(uint64_t address,int RegName);//根据寄存器名字得到对应的变量

uint64_t getSingleIMM(csh handle,const cs_insn *insn); //得到单条指令的立即数

void getName_ClassAndFunc_of_Cpp(char *cpp_name,char *res[2]); //解析函数名从编译后的C++名字,返回字符串数组指针[0]Class[1]func 具体看下面用法

//对整个内核扩展查找特定偏移
void SearchinKEXT(void *bin);

//遍历所有代码查找所有的引用,可以循环引用
void Analysis_Ref(void *bin,uint32_t offset_ref,NSMutableArray *ref_tree,int ref_index,NSMutableArray *ref_alr, char *from_classn);

//显示所有偏移
void ListAllMethods_withOffset(void *bin);

//检查指针指向位置是否在已分配的虚拟内存内,正确返回1
int check_PointerAddrInVM(uint64_t tar_addr);

int check_file_exist(const char *path){
    if(!access(path,F_OK)){
        if(!access(path,R_OK)){
            return 0;
        }
        return -1;
    }
    return -1;
}

int check_file_able_to_write(const char *path){
    if(!access(path,F_OK)){
        printf("%s already have same name file here\n",path);
        return -1;
    }
    return 0;
}

void usage(){
    printf("Usage: maclook4ref <target Mac kext path> <hexadecimal offset of seek> [-p <index>] [-s] [-l]\n");
    printf("\t-p try to generate functions call backtrace\n");
    printf("\t-s print vtable offsets and results, its slow\n");
    printf("\t-l list all vtable offsets, its slow\n\n");
}

int main(int argc, const char * argv[]) {
    
    if(argc==1){
        printf("wrong args\n");usage();exit(1);
    }
    
    if(argc<3){
        printf("Need two args at least\n");usage();exit(1);
    }
    
    int islist = 0;
    
    for(int i=0;i<argc;i++){
        if(!strcmp(argv[i],"-h")){
            usage();exit(1);
        }
        if(!strcmp(argv[i],"-p")){
            Advance_SEARCH_INDEX = (i=i+1)>=argc?-1:(int)strtoull(argv[i],0,10);
            if(Advance_SEARCH_INDEX<0){
                printf("please specify Advance_SEARCH_INDEX correctly\n"); exit(1);
            }
            Advance_SEARCH_MODE = 1;
        }
        if(!strcmp(argv[i],"-s")){
            Print_ALLFUNC_OFFSET = 1;
        }
        if(!strcmp(argv[i],"-l")){
            islist = 1;
        }
    }
    
    if(check_file_exist(argv[1])){
        printf("mac kext file is inexistent or not able to read\n");exit(1);
    }
    
    PATH = argv[1];
    SEARCH_OFFSET = (int)strtoull(argv[2],0,16);
    
    char *kext_path = (char*)PATH;
    
    uint64_t kext_size = FilegetSize(kext_path);
    if(kext_size==0){
        printf("FilegetSize Error\n");
        exit(1);
    }
    
    void *kext_bin = malloc(kext_size);
    FILE *fp = fopen(kext_path,"ro");
    if(fread(kext_bin,1,kext_size,fp)!=kext_size){
        printf("read error\n");
        exit(1);
    }
    fclose(fp);
    
    get_allFunc(kext_bin);
    
    if(!Advance_SEARCH_MODE&&!islist){
        
        SearchinKEXT(kext_bin);
        exit(1);
    }
    
    class_infoDic = [NSMutableDictionary new];
    AnalysisModInitOfKEXT(kext_bin);
    if(islist)
        ListAllMethods_withOffset(kext_bin);
    else
        SearchinKEXT(kext_bin);
    return 0;
}

void get_allFunc(void *firstPage){
    
    all_symbol = [NSMutableDictionary new];
    
    uint64_t textVM = machoGetVMAddr(firstPage,"__TEXT","__text");
    //uint64_t textFileoff = machoGetFileAddr(firstPage,"__TEXT","__text");
    uint64_t textSize = machoGetSize(firstPage,"__TEXT","__text");
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)mh+sizeof(struct mach_header_64));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SYMTAB:{
                struct symtab_command *sym_cmd = (struct symtab_command*)cmd;
                uint32_t symoff = sym_cmd->symoff;
                uint32_t nsyms = sym_cmd->nsyms;
                uint32_t stroff = sym_cmd->stroff;
                uint32_t strsize = sym_cmd->strsize;
                
                //printf("Symbol table is at offset 0x%x (%d), %d entries\n",symoff,symoff,nsyms);
                //printf("String table is at offset 0x%x (%d), %d bytes\n",stroff,stroff,strsize);
                printf("\n");
                for(int i =0;i<nsyms;i++){
                    //64位
                    struct nlist_64 *nn = (void*)((char*)mh+symoff+i*sizeof(struct nlist_64));
                    if(nn->n_value>=textVM&&nn->n_value<(textVM+textSize)){
                        
                        char *def_str = (char*)mh+(uint32_t)nn->n_un.n_strx + stroff;
                        
                        [all_symbol setObject:[NSString stringWithUTF8String:def_str] forKey:[NSNumber numberWithUnsignedLongLong:nn->n_value]];
                    }
                }
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
}

uint64_t machoGetVMAddr(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->vmaddr;
                    }
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->addr;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->vmaddr;
                    }
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->addr;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t machoGetFileAddr(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->fileoff;
                    }
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->offset;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->fileoff;
                    }
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->offset;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t machoGetSize(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->filesize;
                    }
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->size;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->filesize;
                    }
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->size;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t FilegetSize(char *file_path){
    struct stat buf;
    if ( stat(file_path,&buf) < 0 )
    {
        perror(file_path);
        exit(1);
    }
    return buf.st_size;
}

#pragma mark imp:分析每个内核扩展中的ModInit函数,获取类信息
void AnalysisModInitOfKEXT(void *bin){
    csh handle;
    cs_insn *insn;
    size_t count;
    
    if(cs_open(CS_ARCH_X86,CS_MODE_64|CS_MODE_LITTLE_ENDIAN,&handle)!=CS_ERR_OK){
        printf("AnalysisModInitOfKEXT cs_open出错\n");
        exit(1);
    }
    
    cs_option(handle,CS_OPT_DETAIL, CS_OPT_ON);
    
    modInitVM = machoGetVMAddr(bin,"__DATA","__mod_init_func");
    modInitFileoff = machoGetFileAddr(bin,"__DATA","__mod_init_func");
    modInitSize = machoGetSize(bin,"__DATA","__mod_init_func");
    
    //printf("\ntotal %llu modInit in \n",modInitSize/8);
    
    for(int ab=0;ab<modInitSize/8;ab++){
        uint64_t *eachModInitEntry = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,modInitVM+ab*8);
        uint64_t eachModInitFileoff = getfileoffFromAddrOfVM(modInitFileoff,modInitVM,*eachModInitEntry);
        
        int64_t curFunc_FilebaseAddr = eachModInitFileoff;
        int64_t curFunc_VMbaseAddr = (*eachModInitEntry);
        
#pragma mark CLASS_INFO:DEBUG CLASS PRINT
        count = cs_disasm(handle,bin+curFunc_FilebaseAddr,0xfff,curFunc_VMbaseAddr,0,&insn);
        
        size_t j;
        
        rax = 0;
        rbx = 0;
        rcx = 0;
        rdx = 0;
        rdi = 0;
        rsi = 0;
        rbp = 0;
        rsp = 0;
        r8 = 0;
        r9 = 0;
        r10 = 0;
        r11 = 0;
        r12 = 0;
        r13 = 0;
        r14 = 0;
        r15 = 0;
        rip = 0;
        
        for(j=0;j<count;j++){
#pragma mark CLASS_INFO:输出汇编
            //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
            //printf("r0:0x%x r1:0x%x r2:0x%x r3:0x%x\n",r0,r1,r2,r3);
            
            
#pragma mark CLASS_INFO:MOV OP
            if(strstr(insn[j].mnemonic,"mov")){
                int first_reg = getFirstReg(handle,&insn[j]);
                int reg_count = cs_op_count(handle,&insn[j],X86_OP_REG);
                if(reg_count==2){
                    //mov cond1: mov xx <- xx
                }
                else if(reg_count==1){
                    int isCtl_mem = cs_op_count(handle,&insn[j],X86_OP_MEM);
                    int isUse_imm = cs_op_count(handle,&insn[j],X86_OP_IMM);
                    if(isCtl_mem){
                        //mov cond2: mov xx <- [xx,?x]
                        
                    }
                    else if(isUse_imm){
                        //mov cond4: mov xx <- ?imm
                        uint64_t imm = getSingleIMM(handle,&insn[j]);
                        int fir_reg = getFirstReg(handle,&insn[j]);
                        uint64_t* xx = getActualVarFromRegName(insn[j].address,fir_reg);
                        *xx = imm;
                        //printf("0x%llx\n",imm);
                    }
                    
                }
            }
            
#pragma mark CLASS_INFO:LEA OP
            if(strstr(insn[j].mnemonic,"lea")){
                
                int first_reg = getFirstReg(handle,&insn[j]);
                
                int64_t offset = getMEMOPoffset(handle,&insn[j]);
                int offset_reg = getMEMOPregister(handle,&insn[j]);
                
                uint64_t lea_ref_vm;
                
                if(offset_reg==X86_REG_RIP){
                    int64_t cur_ip = insn[j+1].address;
                    lea_ref_vm = cur_ip + offset;
                }
                else{
                    uint64_t* offset_xx = getActualVarFromRegName(insn[j].address,offset_reg);
                    lea_ref_vm = *offset_xx + offset;
                }
                
                uint64_t* xx = getActualVarFromRegName(insn[j].address,first_reg);
                if(xx){
                    *xx = lea_ref_vm;
                }
            }
            
#pragma mark CLASS_INFO:CALL OP
            if(!strcmp(insn[j].mnemonic,"call")){
                char *rsi_classname = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,rsi);
                uint64_t jump_to = getSingleIMM(handle,&insn[j]);
                if(jump_to&&(jump_to==insn[j+1].address)){
                    //调用OSMetaClass
                    //printf("%s\n",rsi_classname);
                    uint64_t *class_self = (uint64_t*)rdi;
                    uint64_t ip_addr = insn[j+2].address;
                    int64_t ip_offset = getMEMOPoffset(handle,&insn[j+1]);
                    //printf("vtable:0x%llx\n",ip_addr+ip_offset);
                    
                    uint64_t vtable_start = 0;
                    
                    uint64_t cur_addr = (uint64_t)ip_addr+ip_offset;
                    uint64_t vtable_end = (uint64_t)ip_addr+ip_offset;
                    
                    //ステップ1: 往上匹配自己类的地址
                    for(;cur_addr>=modInitVM;){
                        //这里是尝试在内存中找到自己类的地址的匹配
                        uint64_t *check_curAddr = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,cur_addr);
                        if(!memcmp(check_curAddr,&class_self,sizeof(class_self))){
                            //找到啦~ じゃ保存起来
                            vtable_start = cur_addr;
                            
                            //exit(1);
                            break;
                        }
                        cur_addr = cur_addr - 0x8;
                    }
                    
                    
                    //ステップ2: 往下去掉空格得到vtable启始位置
                    if(vtable_start){
                        for(int i=0x0;i<0x28;i=i+0x8){
                            uint64_t *check_curAddr = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,vtable_start+i);
                            if(check_PointerAddrInVM((uint64_t)check_curAddr)){
                                if(*check_curAddr==0x0){
                                    vtable_start = vtable_start + i;
                                    for(int z=0x0;z<0x28;z=z+0x8){
                                        uint64_t *check_non_empty = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,vtable_start+z);
                                        if(check_PointerAddrInVM((uint64_t)check_non_empty)){
                                            if(*check_non_empty!=0){
                                                vtable_start = vtable_start + z;
                                                break;
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    
#pragma mark CLASS_INFO:Save to class_infoDic
                    NSNumber *class_size = [NSNumber numberWithUnsignedLongLong:rcx];
                    NSNumber *class_vtable = [NSNumber numberWithUnsignedLongLong:vtable_start];
                    NSNumber *class_vtableEnd = [NSNumber numberWithUnsignedLongLong:vtable_end];
                    
                    [class_infoDic setObject:@[class_size,class_vtable,class_vtableEnd] forKey:[NSString stringWithUTF8String:rsi_classname]];
                    //printf("0x%llx\n",rcx);
                    //printf("%s\n",rsi_classname);
                    //printf("vtable:0x%llx\n",vtable_start);
                }
            }
            
#pragma mark CLASS_INFO:RET OP
            if(strstr(insn[j].mnemonic,"ret")){
                break;
            }
            
        }
        cs_free(insn,count);
        
    }
}

#pragma mark imp:对整个内核扩展查找特定偏移
void SearchinKEXT(void *bin){
    csh handle;
    cs_insn *insn = NULL;
    size_t count = 0;
    
    if(cs_open(CS_ARCH_X86,CS_MODE_64|CS_MODE_LITTLE_ENDIAN,&handle)!=CS_ERR_OK){
        printf("AnalysisModInitOfKEXT cs_open出错\n");
        exit(1);
    }
    
    cs_option(handle,CS_OPT_DETAIL, CS_OPT_ON);
    
    uint64_t modInitVM = machoGetVMAddr(bin,"__TEXT","__text");
    uint64_t modInitFileoff = machoGetFileAddr(bin,"__TEXT","__text");
    uint64_t modInitSize = machoGetSize(bin,"__TEXT","__text");
    
    //printf("\n******** %d:%s *******\n",ab,KextGetBundleID(bin));
    
    size_t read_alr = 0;
    char  *selfFromRdi = "this"; //将这个赋值给寄存器作为存有self/this对象的标记
    NSString *func_n = NULL;
    uint32_t possi_exp_count = 0;
    while(read_alr<modInitSize){
        
        count = cs_disasm(handle,bin+modInitFileoff+read_alr,(modInitSize-read_alr)<500?(modInitSize-read_alr):500,modInitVM+read_alr,0,&insn);
        cs_free(insn,count);
        
        cs_disasm(handle,bin+modInitFileoff+read_alr,(modInitSize-read_alr)<501?(modInitSize-read_alr):510,modInitVM+read_alr,0,&insn);
        
        for(int j=0;j<count;j++){
#pragma mark KEXT_DEBUG:输出汇编
            //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
            
            if([all_symbol objectForKey:[NSNumber numberWithUnsignedLongLong:insn[j].address]]){
                func_n = [all_symbol objectForKey:[NSNumber numberWithUnsignedLongLong:insn[j].address]];
                rax = 0;
                rbx = 0;
                rcx = 0;
                rdx = 0;
                rdi = 1;
                rsi = 0;
                rbp = 0;
                rsp = 0;
                r8 = 0;
                r9 = 0;
                r10 = 0;
                r11 = 0;
                r12 = 0;
                r13 = 0;
                r14 = 0;
                r15 = 0;
                rip = 0;
            }
            
#pragma mark KEXT_DEBUG:PRINT_ALL_REF
            int acount = cs_op_count(handle,&insn[j],X86_OP_MEM);
            if (acount==1){
                int64_t offset = getMEMOPoffset(handle,&insn[j]);
                if(offset==SEARCH_OFFSET){
                    
                    char *res[2];
                    getName_ClassAndFunc_of_Cpp((char*)[func_n UTF8String],res);
                    
                    //printf("aa:%s\n",cs_reg_name(handle,mem_reg));
                    //printf("%d. %d. in %s:\n",possi_exp_count,alrnull_count,[func_n UTF8String]);
                    char *class_name = res[0];
                    char *func_name = res[1];
                    
                    if(Print_ALLFUNC_OFFSET&&class_name&&func_name){
                        uint64_t vtable_vm1 = [[class_infoDic objectForKey:[NSString stringWithUTF8String:class_name]][1] unsignedLongLongValue];
                        uint64_t vtableEnd_vm1 = [[class_infoDic objectForKey:[NSString stringWithUTF8String:class_name]][2] unsignedLongLongValue];
                        uint64_t cur_funcvm1 = [[all_symbol allKeysForObject:func_n][0] unsignedLongLongValue];
                        uint32_t func_offset1 = lookforClass_offsetOfFunc(bin,vtable_vm1,vtableEnd_vm1,cur_funcvm1);
                        if(func_offset1==-1)
                            printf("%d.in [?]%s::%s\n",possi_exp_count,class_name,func_name);
                        else
                            printf("%d.in [0x%x]%s::%s\n",possi_exp_count,func_offset1,class_name,func_name);
                    }
                    else{
                        printf("%d.in %s::%s\n",possi_exp_count,class_name,func_name);
                    }
                    possi_exp_count++;
                    
                    for(int i=(List_INSTRUCTION/2);i>=0;i--){
                        if(i||!Color_mark_ENABLE)
                            printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j-i].address,insn[j-i].mnemonic,insn[j-i].op_str);
                        else
                            printf(COLOR_RED "0x%"PRIX64":\t%s\t\t%s\n" COLOR_OFF,insn[j-i].address,insn[j-i].mnemonic,insn[j-i].op_str);
                    }
                    
                    for(int i=1;i<(List_INSTRUCTION/2);i++){
                        printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j+i].address,insn[j+i].mnemonic,insn[j+i].op_str);
                    }
                    
                    printf("\n\n");
                    
                    
                    if(Advance_SEARCH_MODE){
                        
                        if(possi_exp_count==(Advance_SEARCH_INDEX+1)){
                            
                            if(!class_name||!func_name)
                                goto search_failed;
                            
                            uint64_t vtable_vm = [[class_infoDic objectForKey:[NSString stringWithUTF8String:class_name]][1] unsignedLongLongValue];
                            uint64_t vtableEnd_vm = [[class_infoDic objectForKey:[NSString stringWithUTF8String:class_name]][2] unsignedLongLongValue];
                            uint64_t cur_funcvm = [[all_symbol allKeysForObject:func_n][0] unsignedLongLongValue];
                            
                            if(!vtable_vm||!cur_funcvm){
                            search_failed:
                                printf("Advance SEARCH failed, quit\n"); exit(1);
                            }
                            else{
                                uint32_t func_offset = lookforClass_offsetOfFunc(bin,vtable_vm,vtableEnd_vm,cur_funcvm);
                                
                                NSMutableArray *ref_tree = [NSMutableArray new];
                                NSMutableArray *ref_alr = [NSMutableArray new];
                                
                                Analysis_Ref(bin, func_offset, ref_tree, 0, ref_alr, class_name);
                                
                                //hard to reach here, alwasy trap in a loop in the Analysis_Ref
                                printf("Advance SEARCH done, quit\n"); exit(1);
                            }
                        }
                        
                    }
                }
            }
            
            
        }
        read_alr = read_alr + ((modInitSize-read_alr)>=500?500:(modInitSize-read_alr));
        
        cs_free(insn,count);
    }
}

#pragma mark imp:遍历所有代码查找所有的引用,可以循环引用
void Analysis_Ref(void *bin,uint32_t offset_ref,NSMutableArray *ref_tree,int ref_index,NSMutableArray *ref_alr, char *from_classn){
    
#pragma mark 判断引用上限
    
    //ref_index为循环深度,数值越大,说明当前结果越不可靠
    if(ref_index==2){
        //停止继续循环
        return;
    }
    
    ref_index++;
    csh handle;
    cs_insn *insn = NULL;
    size_t count = 0;
    
    if(cs_open(CS_ARCH_X86,CS_MODE_64|CS_MODE_LITTLE_ENDIAN,&handle)!=CS_ERR_OK){
        printf("Analysis_Ref cs_open出错\n");
        exit(1);
    }
    
    cs_option(handle,CS_OPT_DETAIL, CS_OPT_ON);
    
    uint64_t modInitVM = machoGetVMAddr(bin,"__TEXT","__text");
    uint64_t modInitFileoff = machoGetFileAddr(bin,"__TEXT","__text");
    uint64_t modInitSize = machoGetSize(bin,"__TEXT","__text");
    
    NSMutableArray *ref_list = [NSMutableArray new];
    
    size_t read_alr = 0;
    NSString *func_n = NULL;
    uint32_t possi_exp_count = 0;
    while(read_alr<modInitSize){
        
        count = cs_disasm(handle,bin+modInitFileoff+read_alr,(modInitSize-read_alr)<500?(modInitSize-read_alr):500,modInitVM+read_alr,0,&insn);
        cs_free(insn,count);
        
        cs_disasm(handle,bin+modInitFileoff+read_alr,(modInitSize-read_alr)<501?(modInitSize-read_alr):510,modInitVM+read_alr,0,&insn);
        
        for(int j=0;j<count;j++){
#pragma mark LOOKFOR:输出汇编
            //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
            
            if([all_symbol objectForKey:[NSNumber numberWithUnsignedLongLong:insn[j].address]]){
                //printf("YEAH:%s\n",[func_n UTF8String]);
                func_n = [all_symbol objectForKey:[NSNumber numberWithUnsignedLongLong:insn[j].address]];
                rax = 0;
                rbx = 0;
                rcx = 0;
                rdx = 0;
                rdi = 1;
                rsi = 0;
                rbp = 0;
                rsp = 0;
                r8 = 0;
                r9 = 0;
                r10 = 0;
                r11 = 0;
                r12 = 0;
                r13 = 0;
                r14 = 0;
                r15 = 0;
                rip = 0;
            }
            
#pragma mark LOOKFOR:PRINT_ALL_REF
            int acount = cs_op_count(handle,&insn[j],X86_OP_MEM);
            if (acount==1){
                int64_t offset = getMEMOPoffset(handle,&insn[j]);
                if(offset==offset_ref){ //在这里
                    char *res[2];
                    getName_ClassAndFunc_of_Cpp((char*)[func_n UTF8String],res);
                    
                    if(strcmp(res[1],"free")){
                        //过滤free调用
                        
                        char *class_name = res[0];
                        char *func_name = res[1];
                        
                        //if(possi_exp_count==0)
                        //  printf("- - - - - -\n");
                        if(!class_name||!func_name)
                            return;
                        
                        uint64_t vtable_vm = [[class_infoDic objectForKey:[NSString stringWithUTF8String:class_name]][1] unsignedLongLongValue];
                        uint64_t vtableEnd_vm = [[class_infoDic objectForKey:[NSString stringWithUTF8String:class_name]][2] unsignedLongLongValue];
                        uint64_t cur_funcvm = [[all_symbol allKeysForObject:func_n][0] unsignedLongLongValue];
                        
                        if(!vtable_vm||!cur_funcvm){
                            return;
                        }
                        
                        uint32_t func_offset = lookforClass_offsetOfFunc(bin,vtable_vm,vtableEnd_vm,cur_funcvm);
                        
                        //printf("func_offset: 0x%x\n",func_offset);
                        
                        NSMutableDictionary *ref_info = [NSMutableDictionary new];
                        [ref_info setObject:[NSString stringWithUTF8String:class_name] forKey:@"class_name"];
                        [ref_info setObject:[NSString stringWithUTF8String:func_name] forKey:@"func_name"];
                        [ref_info setObject:[NSNumber numberWithUnsignedInt:func_offset] forKey:@"func_offset"];
                        [ref_info setObject:[NSNumber numberWithUnsignedLongLong:insn[j].address] forKey:@"ref_addr"];
                        
                        
                        [ref_list addObject:ref_info];
                        
                        possi_exp_count++;
                    }
                    
                    /*for(int i=(List_INSTRUCTION/2);i>=0;i--){
                     if(i||!Color_mark_ENABLE)
                     printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j-i].address,insn[j-i].mnemonic,insn[j-i].op_str);
                     else
                     printf(COLOR_RED "0x%"PRIX64":\t%s\t\t%s\n" COLOR_OFF,insn[j-i].address,insn[j-i].mnemonic,insn[j-i].op_str);
                     }
                     
                     for(int i=1;i<(List_INSTRUCTION/2);i++){
                     printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j+i].address,insn[j+i].mnemonic,insn[j+i].op_str);
                     }*/
                }
            }
            
            
            
        }
        read_alr = read_alr + ((modInitSize-read_alr)>=500?500:(modInitSize-read_alr));
        
        cs_free(insn,count);
    }
    
    //这里开始处理引用列表1
#pragma mark LOOKFOR:处理引用列表
    if([ref_list count]>0){
        //NSLog(@"ppp %@",ref_list);
        int only_sing_ref = 0;
        //int has_branch = 0;
        
        if([ref_list count]==1)
            only_sing_ref = 1;
        
        
        for(int i=0;i<[ref_list count];i++){
            NSMutableArray *sub_ref_tree = [NSMutableArray new];
            NSMutableDictionary *single_node = ref_list[i];
            [sub_ref_tree addObject:single_node];
            [ref_tree addObject:sub_ref_tree];
            uint32_t next_offset = [[ref_list[i] objectForKey:@"func_offset"] unsignedIntValue];
            
            //查看这次偏移是否在保存列表里,如果存在,意味接下来进行的操作是相同的,因为查找系统是基于偏移地址的
            for(int i=0;i<[ref_alr count];i++){
                uint32_t save_offset = [ref_alr[i] unsignedIntValue];
                if(next_offset==save_offset){
                    continue;
                }
            }
            
            
            //记录这次偏移
            [ref_alr addObject:[NSNumber numberWithUnsignedInt:next_offset]];
            
            //如果小于0x10也不行
            if(next_offset<0x10){
                continue;
            }
            
#pragma mark 判断引用条件
            //当引用深度大于3时,只会显示2条引用结果
            if(ref_index>3&&i>2){
                return;
            }
            
            const char *class_name = [[single_node objectForKey:@"class_name"] UTF8String];
            const char *func_name = [[single_node objectForKey:@"func_name"] UTF8String];
            uint32_t func_offset = [[single_node objectForKey:@"func_offset"] unsignedIntValue];
            uint64_t ref_addr = [[single_node objectForKey:@"ref_addr"] unsignedLongLongValue];
            printf("|");
            for(int i=0;i<ref_index;i++){
                printf("- ");
            }
            
            if(func_offset==-1)do{
                if(!strcmp(class_name, from_classn)&&Color_mark_ENABLE)
                    printf("[?]"COLOR_RED"%s::%s"COLOR_OFF"(0x%llx)\n",class_name,func_name,ref_addr);
                else
                    printf("[?]%s::%s (0x%llx)\n",class_name,func_name,ref_addr);
            }while(0);
            else
                do{
                    if(!strcmp(class_name, from_classn)&&Color_mark_ENABLE)
                        printf("[0x%x]"COLOR_RED"%s::%s"COLOR_OFF"(0x%llx)\n",func_offset,class_name,func_name,ref_addr);
                    else
                        printf("[0x%x]%s::%s (0x%llx)\n",func_offset,class_name,func_name,ref_addr);
                }while(0);
            
            Analysis_Ref(bin, next_offset, sub_ref_tree, ref_index, ref_alr, from_classn);
        }
        //end of "if(only_sing_ref||has_branch)"
    }
}

//显示所有偏移
#pragma mark imp:显示所有偏移
void ListAllMethods_withOffset(void *bin){
    NSArray *all_funcname = [all_symbol allValues];
    for(int i=0;i<[all_funcname count];i++){
        NSString *func_n = all_funcname[i];
        
        char *res[2];
        getName_ClassAndFunc_of_Cpp((char*)[func_n UTF8String],res);
        
        char *class_name = res[0];
        char *func_name = res[1];
        
        if(class_name&&func_name){
            uint64_t vtable_vm = [[class_infoDic objectForKey:[NSString stringWithUTF8String:class_name]][1] unsignedLongLongValue];
            uint64_t vtableEnd_vm = [[class_infoDic objectForKey:[NSString stringWithUTF8String:class_name]][2] unsignedLongLongValue];
            uint64_t cur_funcvm = [[all_symbol allKeysForObject:func_n][0] unsignedLongLongValue];
            uint32_t func_offset = lookforClass_offsetOfFunc(bin, vtable_vm, vtableEnd_vm, cur_funcvm);
            if(func_offset==-1)
                printf("%d [?]%s::%s\n",i,class_name,func_name);
            else
                printf("%d [0x%x]%s::%s\n",i,func_offset,class_name,func_name);
        }
    }
}

//转换汇编的虚拟内存地址,返回在内存中的实际内容
#pragma mark imp:转换汇编的虚拟内存地址,返回在内存中的实际内容
void* getMemFromAddrOfVM(void* bin,uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr){
    uint64_t offset = cur_VMAddr - CurFunc_VMbaseAddr;
    return bin+CurFunc_FilebaseAddr+offset;
}

//转换虚拟内存地址,返回文件中偏移地址
#pragma mark imp:转换虚拟内存地址,返回文件中偏移地址
uint64_t getfileoffFromAddrOfVM(uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr){
    return (uint64_t)((uint64_t)CurFunc_FilebaseAddr+((uint64_t)cur_VMAddr-(uint64_t)CurFunc_VMbaseAddr));
}

//得到str/ldr指令的内存偏移数
#pragma mark imp:得到str/ldr指令的内存偏移数
int64_t getMEMOPoffset(csh handle,const cs_insn *insn){
    int64_t offset;
    int acount = cs_op_count(handle,insn,X86_OP_MEM);
    if (acount) {
        if(acount>1)
            printf("getMEMOPoffset 多个偏移量\n");
        for (int i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,X86_OP_MEM,i);
            offset = insn->detail->x86.operands[index].mem.disp;
            return offset;
        }
    }
    return 0;
}

//得到lea指令的偏移寄存器
#pragma mark imp:得到lea指令的偏移寄存器
int getMEMOPregister(csh handle,const cs_insn *insn){
    uint32_t i,offset;
    int acount = cs_op_count(handle,insn,X86_OP_MEM);
    if (acount) {
        if(acount>1)
            printf("getMEMOPregister 多个偏移量\n");
        for (i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,X86_OP_MEM,i);
            offset = insn->detail->x86.operands[index].mem.base;
            return offset;
        }
    }
    return 0;
}

//得到第一个寄存器
#pragma mark imp:得到第一个寄存器
int getFirstReg(csh handle,const cs_insn *insn){
    int i,s_reg;
    int acount = cs_op_count(handle,insn,X86_OP_REG);
    if (acount) {
        for (i = 1; i < acount + 1;i++) {
            int index = cs_op_index(handle,insn,X86_OP_REG,i);
            if(i==1){
                s_reg = insn->detail->x86.operands[index].reg;
                return s_reg;
            }
        }
    }
    return 0;
}

//得到第二个寄存器
#pragma mark imp:得到第二个寄存器
int getSecondReg(csh handle,const cs_insn *insn){
    int i,s_reg;
    int acount = cs_op_count(handle,insn,X86_OP_REG);
    if (acount) {
        if(acount<2)
            printf("getSecondReg 少于一个寄存器\n");
        for (i = 1; i < acount + 1;i++) {
            int index = cs_op_index(handle,insn,X86_OP_REG,i);
            if(i==2){
                s_reg = insn->detail->x86.operands[index].reg;
                return s_reg;
            }
        }
    }
    return 0;
}

//根据寄存器名字得到对应的变量
#pragma mark imp:根据寄存器名字得到对应的变量
uint64_t* getActualVarFromRegName(uint64_t address,int RegName){
    switch (RegName) {
        case X86_REG_RAX:
            return &rax;
            break;
        case X86_REG_RBX:
            return &rbx;
            break;
        case X86_REG_RCX:
            return &rcx;
            break;
        case X86_REG_RDX:
            return &rdx;
            break;
        case X86_REG_RDI:
            return &rdi;
            break;
        case X86_REG_RSI:
            return &rsi;
            break;
        case X86_REG_RBP:
            return &rbp;
            break;
        case X86_REG_RSP:
            return &rsp;
            break;
        case X86_REG_R8:
            return &r8;
            break;
        case X86_REG_R9:
            return &r9;
            break;
        case X86_REG_R10:
            return &r10;
            break;
        case X86_REG_R11:
            return &r11;
            break;
        case X86_REG_R12:
            return &r12;
            break;
        case X86_REG_R13:
            return &r13;
            break;
        case X86_REG_R14:
            return &r14;
            break;
        case X86_REG_R15:
            return &r15;
            break;
        case X86_REG_RIP:
            return &rip;
            break;
        default:
            break;
    }
    
#pragma mark USE_32Bit_Register
    switch (RegName) {
        case X86_REG_EAX:
            return &rax;
            break;
        case X86_REG_EBX:
            return &rbx;
            break;
        case X86_REG_ECX:
            return &rcx;
            break;
        case X86_REG_EDX:
            return &rdx;
            break;
        case X86_REG_EDI:
            return &rdi;
            break;
        case X86_REG_ESI:
            return &rsi;
            break;
        default:
            break;
    }
    
    return NULL;
}

#pragma mark imp:解析函数名从编译后的C++名字:
void getName_ClassAndFunc_of_Cpp(char *cpp_name,char *res[2]){
    
    if(!res){
        printf("getName_ClassAndFunc_of_Cpp NULL arg: char **res[2]\n");
        exit(1);
    }
    
    char *class_name=0,*func_name=0;
    
    NSString *orig_str = [NSString stringWithUTF8String:cpp_name];
    NSString *tmpStr;
    NSScanner *scanner = [NSScanner scannerWithString:orig_str];
    NSCharacterSet *num = [NSCharacterSet characterSetWithCharactersInString:@"0123456789"];
    [scanner scanUpToCharactersFromSet:num intoString:NULL];
    
    [scanner scanCharactersFromSet:num intoString:&tmpStr];
    if(tmpStr){
        //检查长度过滤出类名,裁剪原字符串
        size_t used_len = [scanner scanLocation]+[tmpStr integerValue];
        if(used_len<=[orig_str length]){
            class_name = (char*)[[orig_str substringWithRange:NSMakeRange([scanner scanLocation],[tmpStr integerValue])] UTF8String];
            //printf("class_name: %s\n",class_name);
            orig_str = [orig_str substringWithRange:NSMakeRange(used_len,[orig_str length]-used_len)];
            scanner = [NSScanner scannerWithString:orig_str];
            [scanner scanUpToCharactersFromSet:num intoString:NULL];
        }
    }
    
    if(class_name){
        tmpStr = @"";
        [scanner scanCharactersFromSet:num intoString:&tmpStr];
        if(tmpStr){
            //检查长度过滤出函数名,检查そして收尾
            size_t used_len = [scanner scanLocation]+[tmpStr integerValue];
            if(used_len<=[orig_str length]){
                func_name = (char*)[[orig_str substringWithRange:NSMakeRange([scanner scanLocation],[tmpStr integerValue])] UTF8String];
                //printf("func_name: %s\n",func_name);
            }
        }
    }
    
    if(class_name&&func_name){
        res[0] = class_name;
        res[1] = func_name;
        return;
        //printf("class_name: %s\n",class_name);
        //printf("func_name: %s\n",func_name);
    }
    res[0] = 0;
    res[1] = 0;
}

//得到单条指令的立即数
#pragma mark imp:得到单条指令的立即数
uint64_t getSingleIMM(csh handle,const cs_insn *insn){
    int i;
    uint64_t imm;
    int acount = cs_op_count(handle,insn,X86_OP_IMM);
    if (acount) {
        if(acount>1)
            printf("getSingleIMM 多个立即数\n");
        for (i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,X86_OP_IMM,i);
            imm = insn->detail->x86.operands[index].imm;
            return imm;
        }
    }
    return 0;
}

#pragma mark imp:对类的vtable查找特定函数偏移
uint32_t lookforClass_offsetOfFunc(void *bin,uint64_t vtable_vm,uint64_t vtableEnd_vm,uint64_t func_vm){
    //IDA和hopper中是不一样的 (IDA的优化很方便, 而hopper没有)
    //在C++的函数表上会被填入外部继承的内容,也就是没有被重写的函数,也就是IDA中标为粉色的函数名,实际二进制中为0x0
    //那就得想个判断的方法:
    //在分析每个类的地方,可以得到vtable结束的位置,保存那个位置
    for(uint64_t i=vtable_vm;i<=vtableEnd_vm;i=i+0x8){
        uint64_t *check_curAddr = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,i);
        if(check_PointerAddrInVM((uint64_t)check_curAddr)){
            /*
             //在外部引用类继承的函数都为空,所以这个判断没有意义
             if(*check_curAddr==0x0){
             //    break;
             }
             */
            
            //printf("lll:0x%llx-0x%llx\n",check_curAddr,*check_curAddr);
            if(*check_curAddr==func_vm){
                return (uint32_t)(i-vtable_vm);
            }
        }
    }
    return -1;
}

//检查指针指向位置是否在已分配的虚拟内存内,正确返回1
#pragma mark imp:检查指针指向位置是否在已分配的虚拟内存内,正确返回1
int check_PointerAddrInVM(uint64_t tar_addr)
{
    //仅限使用64位程序,32位请修改
    int pid = 0;
    pid_for_task(mach_task_self(),&pid);
    
    vm_map_t task = 0;
    task_for_pid(mach_task_self(),pid,&task);
    
    int avai = 0;
    
    kern_return_t ret;
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0;
    while (1) {
        ret = vm_region_recurse_64(task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count);
        
        if (ret != KERN_SUCCESS)
            break;
        if(addr>0x7fff00000000)
            break;
        if(tar_addr>=addr&&tar_addr<=addr+size){
            avai = 1;
        }
        //printf("region 0x%lx - 0x%lx\n",addr,addr+size);
        addr = addr + size;
    }
    
    if(avai==1)
        return 1;
    else
        return 0;
    
    return 0;
}