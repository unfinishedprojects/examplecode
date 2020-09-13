#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>



int run(char* str){
    int i;
    char *elf_base_addr=(char*)0x400000;
    // parse ELF header and find the start of program headers and number of pheaders
    Elf64_Ehdr ehdr=*(Elf64_Ehdr*)(elf_base_addr);
    printf("e_phoff: 0x%x\ne_phnum: 0x%x\n",ehdr.e_phoff,ehdr.e_phnum);

    // search proram header for the dynamic section entry
    Elf64_Phdr* phdr= (Elf64_Phdr*)(elf_base_addr+ehdr.e_phoff);
    Elf64_Phdr pt_dynamic;

    for(i=0;i<ehdr.e_phnum;i++){
        if(phdr[i].p_type==PT_DYNAMIC){
            printf("PHDR:\n- p_type: 0x%x\n- p_vaddr: 0x%x\n- p_memsz: 0x%x\n\n",
                        phdr[i].p_type, phdr[i].p_vaddr, phdr[i].p_memsz);
            pt_dynamic=phdr[i];
            break;
        }
    }

    // search the dynamic section for PLTGOT, STRTAB, and SYMTAB
    char  *dt_strtab;
    int64_t dt_strsz, dt_syment, dt_pltrelsz, dt_relaent;
    Elf64_Sym *dt_symtab;
    Elf64_Rela *dt_jmprel;

    for(i=0; i<pt_dynamic.p_memsz; i+=sizeof(Elf64_Dyn)){
        Elf64_Dyn dynent = *(Elf64_Dyn*) (pt_dynamic.p_vaddr + i);
        switch(dynent.d_tag){
            case DT_STRTAB:
                dt_strtab=(char*)dynent.d_un.d_ptr;
                break;
            case DT_SYMTAB:
                dt_symtab=(Elf64_Sym*)dynent.d_un.d_ptr;
                break;
            case DT_STRSZ:
                dt_strsz=dynent.d_un.d_val;
                break;
            case DT_SYMENT:
                dt_syment=dynent.d_un.d_val;
                break;
            case DT_RELAENT:
                dt_relaent=dynent.d_un.d_val;
                break;
            case DT_PLTRELSZ:
                dt_pltrelsz=dynent.d_un.d_val;
                break;
            case DT_JMPREL:
                dt_jmprel=(Elf64_Rela*)dynent.d_un.d_ptr;
        }
    }
    printf("STRTAB: %p (len: 0x%x)\n",dt_strtab, dt_strsz);
    printf("SYMTAB: %p (entries: 0x%x)\n",dt_symtab,dt_syment);
    printf("DT_JMPREL: %p (len: 0x%x)\n", dt_jmprel, dt_pltrelsz);
    printf("DT_RELAENT: %d\n", dt_relaent);

    // parse SYMTAB looking for `system` and `strlen`
    int strlen_idx, system_idx;
    for(i=0; i<dt_syment; i++){
        if(ELF64_ST_BIND(dt_symtab[i].st_info)==STB_GLOBAL && ELF64_ST_TYPE(dt_symtab[i].st_info)==STT_FUNC){
            if(strcmp("system",dt_strtab+dt_symtab[i].st_name)==0){
                system_idx=i;
            }
            if(strcmp("strlen",dt_strtab+dt_symtab[i].st_name)==0){
                strlen_idx=i;
            }
        }
    }
    printf("system idx: %d\nstrlen idx: %d\n\n", system_idx, strlen_idx);

    
    // parse PLTREL
    int64_t *system_rela, *strlen_rela;
    for(i=0; i<dt_pltrelsz/dt_relaent; i++){
        if(ELF64_R_SYM(dt_jmprel[i].r_info)==strlen_idx){
            strlen_rela=(int64_t*)dt_jmprel[i].r_offset;
        }
        if(ELF64_R_SYM(dt_jmprel[i].r_info)==system_idx){
            system_rela=(int64_t*)dt_jmprel[i].r_offset;
        }
    }

   
    printf("system@GOT: %p strlen@GOT: %p\n", system_rela, strlen_rela);

    // overwrite strlen entry with system
    printf("before... %p: %p\n", strlen_rela, *strlen_rela);
    *strlen_rela=*system_rela;
    printf("after... %p: %p\n\n", strlen_rela, *strlen_rela);
    
    
    printf("calling strlen...\n\n");
    char *cmd="id";
    i=strlen(cmd);
}

// make sure system is actually referenced in the program
int do_stuff(){
    system("echo done");
}

int main(){
    char data[256];
    run("id");
    do_stuff();
}






