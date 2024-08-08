#include <windows.h>
#include <stdio.h>
#include <string>
#include <map>
#include <functional>
#include <iostream>
#include "vendor/memory_signature.hpp"
#include "vendor/MinHook.h"

using std::string;


DWORD GetModuleLen(HMODULE hModule)
{
	PBYTE pImage = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeader;
	pImageDosHeader = (PIMAGE_DOS_HEADER)pImage;
	if(pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}
	pImageNtHeader = (PIMAGE_NT_HEADERS)&pImage[pImageDosHeader->e_lfanew];
	if(pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}
	return pImageNtHeader->OptionalHeader.SizeOfImage;
}

uint8_t* find_pattern(HMODULE module,const char* pattern){
	auto* begin    = (uint8_t*)module;
	const auto end = begin + GetModuleLen(module);
	jm::memory_signature sig(pattern);
	uint8_t* res_addr =  sig.find(begin,end);
	if(res_addr&&(pattern[0]=='E'||pattern[0]=='e')&&pattern[1]=='8'){
		int32_t rva = *(int32_t*)(res_addr+1);
		printf("%p -> %x\n",res_addr,rva);
		res_addr = res_addr + rva +5;
	}
	return res_addr;
}


void test(int i){
    printf("%d\n",i);
    if(i>=20)return;
	auto ptest = (void*)&test;
    ((decltype(test)*)(ptest))(i+1);
    
}

#define NAME(variable) (#variable)


static class HookManager{
public:
	class Hook{
	
	public:
		char*  m_name  =nullptr;
		void*  m_addr  =nullptr;
		void*  m_orig  =nullptr;
		void*  m_detour=nullptr;
        int    m_nowlayer=0;
		Hook(char* name,void* addr,void*detour){
			m_name=name;
			m_addr=addr;
			m_detour=detour;
			if(m_addr){

				if (MH_CreateHook(addr, m_detour, (void**)(&m_orig)) != MH_OK)printf("[Hook] %s MH_CreateHook Error\n",m_name);
				else if (MH_EnableHook(m_addr) != MH_OK) printf("[Hook] %s - MH_EnableHook Error\n",m_name);
				else printf("[Hook] %s Hooked (%p)->(%p) new_entry:%p\n",m_name,addr, &m_detour, m_orig);
			}
		}
	};


	std::map<void*,Hook*> hooks;
	bool minhookInited;
	HookManager(){
		if (MH_Initialize() != MH_OK) { printf("MH_Initialize Error\n");  minhookInited = false;}
		else { printf("MH_Initialize OJBK\n"); minhookInited = true;}
	};

	template<typename F>
	F* Orignal(F* detour){
        auto it = hooks.find(detour);
    	if (it == hooks.end()) {
			printf("Not Found\n");
    	    return nullptr;
    	}
        return (decltype(detour))(hooks[detour]->m_orig);
	};

	template<typename F>
	Hook* GetHook(F* detour,...){
        auto it = hooks.find(detour);
    	if (it == hooks.end()) {
			printf("Not Found\n");
    	    return nullptr;
    	}
        return hooks[detour];
	};

    template<typename F>
	F* AddHook(void* target,F* detour, char* name){
        
		auto it = hooks.find(detour);
    	if (it != hooks.end()) {
			printf("Already Hooked\n");
    	    return (decltype(detour))hooks[detour]->m_orig;
    	}
		hooks[detour] = new Hook(name, target, (void*)detour);
        printf("Hook %s %p->%p orig(%p)\n", name,target, detour,hooks[detour]->m_orig);
		return (decltype(detour))hooks[detour]->m_orig;
	};


    template<typename F>
	F* AddHook(char* apifullname_raw, F* detour, char* name){
        std::string apifullname(apifullname_raw);
        size_t pos = apifullname.find('!');
        if (pos != std::string::npos) {
            std::string moduleName = apifullname.substr(0, pos);
            std::string apiName = apifullname.substr(pos + 1);
            if(HMODULE hModule = GetModuleHandleA(moduleName.c_str())){
                if(auto apiAddress = GetProcAddress(hModule,apiName.c_str()))
                    return AddHook(apiAddress,detour,name);
                else
                    printf("%s NotFound\n",apiName.c_str());
            }else{
                printf("%s NotFound\n",moduleName.c_str());
            }
        }
        pos = apifullname.find('#');
        if (pos != std::string::npos) {
            std::string moduleName = apifullname.substr(0, pos);
            std::string apiName = apifullname.substr(pos + 1);
            if(HMODULE hModule = GetModuleHandleA(moduleName.c_str())){
                if(auto apiAddress = find_pattern(hModule,apiName.c_str()))
                    return AddHook(apiAddress,detour,name);
                else
                    printf("%s NotFound\n",apiName.c_str());
            }else{
                printf("%s NotFound\n",moduleName.c_str());
            }
        }
        else{
            printf("apifullname error\n");
        }
        return nullptr;
	};
    


} hk;
void mytest(int x){
    auto myhk = hk.GetHook(mytest);
    if(myhk){
        if(myhk->m_nowlayer==0)
            printf("enter hook\n");
        myhk->m_nowlayer++;
    }
    if(myhk&&myhk->m_nowlayer>1)
        hk.Orignal(mytest)(x);
    else{
        //first in
        hk.Orignal(mytest)(x+10);
    }
        
    if(myhk){
        myhk->m_nowlayer--;
        if(myhk->m_nowlayer==0)
            printf("leave hook\n");
    }

}
NTSTATUS NTAPI NtWriteVirtualMemory_detour(
  IN HANDLE               ProcessHandle,
  IN PVOID                BaseAddress,
  IN PVOID                Buffer,
  IN ULONG                NumberOfBytesToWrite,
  OUT PULONG              NumberOfBytesWritten OPTIONAL ){
	printf("[W]%p %p\n",ProcessHandle,BaseAddress);
	return hk.Orignal(NtWriteVirtualMemory_detour)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

int main(){
    printf("xx: %s\n",NAME(mytest));
    hk.AddHook(test,mytest,NAME(test));
    test(1);
    //hk.AddHook("ntdll.dll!NtWriteVirtualMemory",NtWriteVirtualMemory_detour,"NtWriteVirtualMemory");
    //hk.AddHook("ntdll.dll#4C 8B D1 B8 3A 00 00 00",NtWriteVirtualMemory_detour,"NtWriteVirtualMemory");
    hk.AddHook("ntdll.dll#E8 ? ? ? ? 45 33 FF 8B D8",NtWriteVirtualMemory_detour,"NtWriteVirtualMemory");
    return 1;
}