#include <stdio.h>
#include <stdint.h>
#include <Zydis/Zydis.h> 
#include <Windows.h>
#include <stdlib.h>

typedef unsigned long long uint64_t;

typedef struct _ImageSectionInfo
{
	char *SectionAddress;
	int SectionSize;
} ImageSectionInfo;

typedef int (* MsgBoxType)(HWND, LPCTSTR, LPCTSTR, UINT, WORD);

void get_rdata_info(HMODULE handle, ImageSectionInfo* pSectionInfo) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)handle;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)dosHeader + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHdr = (IMAGE_SECTION_HEADER *)(ntHeaders + 1);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		char *name = (char*)pSectionHdr->Name;
		if (memcmp(name, ".rdata", 6) == 0)
		{
			pSectionInfo->SectionAddress = (char *)handle + pSectionHdr->VirtualAddress;
			pSectionInfo->SectionSize = pSectionHdr->Misc.VirtualSize;
			printf("handle: 0x%p\n", handle);
			printf("pSectionHdr->VirtualAddress: 0x%p\n", pSectionHdr->VirtualAddress);
			printf("pSectionHdr->Misc.VirtualSize: 0x%p\n", pSectionHdr->Misc.VirtualSize);
			printf("SectionAddress: 0x%p\n", pSectionInfo->SectionAddress);
			printf("SectionSize: 0x%p\n", pSectionInfo->SectionSize);
			//pSectionInfo = new ImageSectionInfo(".rdata");
			//pSectionInfo->SectionAddress = handle + pSectionHdr->VirtualAddress;

			//**//range of the data segment - something you're looking for**
			//	pSectionInfo->SectionSize = pSectionHdr->Misc.VirtualSize;
			break;
		}
		pSectionHdr++;
	}
	uintptr_t entryPoint =
		(uintptr_t)((uint8_t*)handle + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("Code address: 0x%p\n", ntHeaders->OptionalHeader.BaseOfCode);
	printf("SizeOfCode: 0x%p\n", ntHeaders->OptionalHeader.SizeOfCode);
	printf("Entry point: 0x%p\n", entryPoint);
	printf("selfHandle: 0x%p\n", handle);
	printf("ntHeaders->OptionalHeader.AddressOfEntryPoint: 0x%p\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

void disasm_test(uint8_t *data, size_t length) {
	// Initialize decoder context.
	ZydisDecoder decoder;
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64);

	// Initialize formatter. Only required when you actually plan to
	// do instruction formatting ("disassembling"), like we do here.
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	// Loop over the instructions in our buffer.
	uint64_t instructionPointer = 0x007FFFFFFF400000;
	uint8_t* readPointer = data;
	//size_t length = 1;
	ZydisDecodedInstruction instruction;
	while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, readPointer, length, instructionPointer, &instruction)))
	{
		// Print current instruction pointer.
		printf("%016" PRIX64 "  ", instructionPointer);

		// Format & print the binary instruction 
		// structure to human readable format.
		char buffer[256];
		ZydisFormatterFormatInstruction(
			&formatter, &instruction, buffer, sizeof(buffer));
		puts(buffer);

		readPointer += instruction.length;
		length -= instruction.length;
		instructionPointer += instruction.length;
	}
}

uint32_t to_little(uint32_t num) {
	return ((num >> 24) & 0xff) | // move byte 3 to byte 0
		((num << 8) & 0xff0000) | // move byte 1 to byte 2
		((num >> 8) & 0xff00) | // move byte 2 to byte 1
		((num << 24) & 0xff000000); // byte 0 to byte 3
}

int get_bait_code(uint8_t * trampoline_code_out, uint64_t addr) {
	uint8_t trampoline_code[] =
	{
		0x68, 0x44, 0x33, 0x22, 0x11, // push 0x11223344 (addr_left)
		0xc7, 0x44, 0x24, 0x04, 0x88, 0x77, 0x66, 0x55, //mov dword ptr [rsp+4], 0x55667788 (addr_right)
		0xc3 //ret
	};

	uint32_t addr_right = (uint32_t)(addr & 0xffffffff);
	uint32_t addr_left = (uint32_t)((addr & 0xffffffff00000000) >> 32);

	printf("low_addr: %p\n", addr_left);
	printf("high_addr: %p\n", addr_right);

	*(uint32_t *)&trampoline_code[1] = addr_right;
	*(uint32_t *)&trampoline_code[9] = addr_left;

	//disasm_test(trampoline_code, sizeof(trampoline_code));

	memcpy(trampoline_code_out, trampoline_code, sizeof(trampoline_code));

	return 0;
}

int calc_damaged_instructions(uint8_t *data, size_t len_erased) {
	size_t max_len = 50;
	size_t decoded_len = 0;
	// Initialize decoder context.
	ZydisDecoder decoder;
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64);

	// Initialize formatter. Only required when you actually plan to
	// do instruction formatting ("disassembling"), like we do here.
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	// Loop over the instructions in our buffer.
	uint64_t instructionPointer = 0x007FFFFFFF400000;
	uint8_t* readPointer = data;
	//size_t length = 1;
	ZydisDecodedInstruction instruction;
	while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder, readPointer, max_len, instructionPointer, &instruction)))
	{
		// Print current instruction pointer.
		printf("%016" PRIX64 "  ", instructionPointer);
		
		// Format & print the binary instruction 
		// structure to human readable format.
		char buffer[256];
		ZydisFormatterFormatInstruction(
			&formatter, &instruction, buffer, sizeof(buffer));
		puts(buffer);

		readPointer += instruction.length;
		max_len -= instruction.length;
		instructionPointer += instruction.length;
		decoded_len += instruction.length;
		if (decoded_len >= len_erased) {
			break;
		}
	}

	return decoded_len;
}

LPVOID myVirtualAlloc(SIZE_T size, DWORD protection) {
	LPVOID pAllocated = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	if (!pAllocated) {
		printf("VirtualAlloc error: %d\n", GetLastError());
		exit(-1);
	}

	return pAllocated;
}

void myVirtualProtect(LPVOID lpAddress, SIZE_T size, DWORD protection, DWORD *old_protection) {
	if (!VirtualProtect(lpAddress, size, protection, old_protection)) {
		printf("VirtualProtect error: %d\n", GetLastError());
		exit(-1);
	}
}

int main() {
	uint8_t bait_code[14];
	DWORD dwOldProtect;
	size_t damaged_instructions_len;
	uint64_t * hook_body_offset = 0;
	MsgBoxType MsgBox;
	ImageSectionInfo sectionInfo;

	HMODULE user32 = LoadLibrary("user32.dll");
	MsgBox = GetProcAddress(user32, "MessageBoxExA");
	MsgBox(NULL, "Text", "Caption", 0, 0);

	HMODULE selfHandle = GetModuleHandle(0);
	if (!selfHandle) {
		printf("GetModuleHandle error: %d\n", GetLastError());
		exit(-1);
	}
	
	damaged_instructions_len = calc_damaged_instructions(MsgBox, 14);
	LPVOID pHookBody = myVirtualAlloc(0x1000, PAGE_EXECUTE_READWRITE);

	hook_body_offset = pHookBody;

	uint8_t payload[] = {
		0x48, 0xb8, 0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, // movabs rax, 0x4142434445464748
		0x48, 0x89, 0x02 // mov qword ptr [rdx], rax
	};

	get_rdata_info(selfHandle, &sectionInfo);

	

	// copy payload
	myVirtualProtect((LPVOID)sectionInfo.SectionAddress, sectionInfo.SectionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(hook_body_offset, payload, sizeof(payload));
	hook_body_offset = (char*)pHookBody + sizeof(payload);

	// copy erased instructions from hooked function
	memcpy(hook_body_offset, MsgBox, damaged_instructions_len);
	hook_body_offset = (char*)hook_body_offset + damaged_instructions_len;

	// return to hooked place
	get_bait_code(bait_code, (char*)MsgBox + damaged_instructions_len);
	memcpy(hook_body_offset, bait_code, sizeof(bait_code));
	hook_body_offset = (char*)hook_body_offset + sizeof(bait_code);

	// hook function
	get_bait_code(bait_code, pHookBody);
	myVirtualProtect((LPVOID)(user32 + 0x1000), 0x9d000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(MsgBox, bait_code, sizeof(bait_code));

	

	MsgBox(NULL, "Text After Hook", "After Hook", 0, 0);

	return 0;
}