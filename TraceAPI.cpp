/* Developed by: Banxen */

#include <fstream>
#include <iostream>
#include <string>
#include "pin.H"

using namespace::std;

#define PAGE_ALLIGNMENT 4096

ofstream trace;
ADDRINT pageStartAddress = 0;
BOOL isMainModuleToTrack = 1;
string moduleToTrack;
KNOB<string> moduleNameToTrack(KNOB_MODE_WRITEONCE, "pintool", "m", "", "specify module name to track");
KNOB<string> traceOutputFileName(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify trace output file name");

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
	printf("Caught Exception!");
	trace.flush();
	return EHR_UNHANDLED;
}

string ExtractImageName(string imageNamePath) {
	unsigned int imageNameOffset = imageNamePath.find_last_of("\\") + 1;
	unsigned int dotOffset = imageNamePath.find_last_of(".");
	return imageNamePath.substr(imageNameOffset, dotOffset - imageNameOffset);
}

VOID TraceCall(const ADDRINT callFrom, const ADDRINT callTo) {
	PIN_LockClient();

	IMG callFromImg = IMG_FindByAddress(callFrom);
	IMG callToImg = IMG_FindByAddress(callTo);

	RTN callFromRoutine = RTN_FindByAddress(callFrom);
	RTN callToRoutine = RTN_FindByAddress(callTo);

	if (isMainModuleToTrack) {
		if (IMG_Valid(callFromImg)) {
			if (IMG_Valid(callToImg)) {
				if (callFromRoutine != RTN_Invalid() && callToRoutine != RTN_Invalid()) { // Call is from valid routine to valid routine
					if (IMG_IsMainExecutable(callFromImg) && !IMG_IsMainExecutable(callToImg)) {  // Call is not within the same module
						trace << SEC_Name(RTN_Sec(callFromRoutine)) << ", ";
						trace << "0x" << std::hex << callFrom - IMG_StartAddress(callFromImg) << ", ";
						trace << ExtractImageName(IMG_Name(callToImg));
						trace << "." << RTN_FindNameByAddress(callTo) << "+" << callTo - RTN_Address(callToRoutine) << "\n";
					}
				}
			}
			else { // Call to some runtime code
				if (IMG_IsMainExecutable(callFromImg)) {  // Call is from Main module code to some runtime code
					trace << ".shellcode" << ", ";
					trace << "0x" << std::hex << callFrom - IMG_StartAddress(callFromImg) << ", ";
					pageStartAddress = (callTo / PAGE_ALLIGNMENT)*PAGE_ALLIGNMENT;
					trace << std::hex << pageStartAddress << "." << "0x" << std::hex << callTo - pageStartAddress << "\n";
				}
			}
		}
		else {  // Call came from some runtime code
			if (IMG_Valid(callToImg)) { // Call is from runtime code to some valid module
				if (callToRoutine != RTN_Invalid()) { // Call is to valid routine
					if (!IMG_IsMainExecutable(callToImg)) { // Valid module is not the Main module [Just not logging call from runtime code back to Main module]					
						if (!(callFrom > pageStartAddress && callFrom < pageStartAddress + PAGE_ALLIGNMENT)) {
							pageStartAddress = (callFrom / PAGE_ALLIGNMENT)*PAGE_ALLIGNMENT;
						}
						trace << ".shellcode" << ", ";
						trace << std::hex << pageStartAddress << "." << "0x" << std::hex << callFrom - pageStartAddress << ", ";
						trace << ExtractImageName(IMG_Name(callToImg));
						trace << "." << RTN_FindNameByAddress(callTo) << "+" << callTo - RTN_Address(RTN_FindByAddress(callTo)) << "\n";
					}
				}
			}
		}
	}
	else {
		if (IMG_Valid(callFromImg)) {
			if (IMG_Valid(callToImg)) {
				if (callFromRoutine != RTN_Invalid() && callToRoutine != RTN_Invalid()) { // Call is from valid routine to valid routine
					if ((IMG_Name(callFromImg).find(moduleToTrack) != string::npos) && (IMG_Name(callToImg).find(moduleToTrack) == string::npos)) { // Call is not within the same module
						trace << SEC_Name(RTN_Sec(RTN_FindByAddress(callFrom))) << ", ";
						trace << "0x" << std::hex << callFrom - IMG_StartAddress(callFromImg) << ", ";
						trace << ExtractImageName(IMG_Name(callToImg));
						trace << "." << RTN_FindNameByAddress(callTo) << "+" << callTo - RTN_Address(RTN_FindByAddress(callTo)) << "\n";
					}
				}
			}
			else { // Call to some runtime code
				if (IMG_Name(callFromImg).find(moduleToTrack) != string::npos) { // Call is from specified module code to some runtime code
					trace << ".shellcode" << ", ";
					trace << "0x" << std::hex << callFrom - IMG_StartAddress(callFromImg) << ", ";
					pageStartAddress = (callTo / PAGE_ALLIGNMENT)*PAGE_ALLIGNMENT;
					trace << std::hex << pageStartAddress << "." << "0x" << std::hex << callTo - pageStartAddress << "\n";
				}
			}
		}
		else { // Call came from some runtime code
			if (IMG_Valid(callToImg)) { // Call is from runtime code to some valid module
				if (callToRoutine != RTN_Invalid()) { // Call is to valid routine
					if (IMG_Name(callToImg).find(moduleToTrack) == string::npos) { // Valid module is not the specified module [Just not logging call from runtime code back to specified module]				
						if (!(callFrom > pageStartAddress && callFrom < pageStartAddress + PAGE_ALLIGNMENT)) {
							pageStartAddress = (callFrom / PAGE_ALLIGNMENT)*PAGE_ALLIGNMENT;
						}
						trace << ".shellcode" << ", ";
						trace << std::hex << pageStartAddress << "." << "0x" << std::hex << callFrom - pageStartAddress << ", ";
						trace << ExtractImageName(IMG_Name(callToImg));
						trace << "." << RTN_FindNameByAddress(callTo) << "+" << callTo - RTN_Address(RTN_FindByAddress(callTo)) << "\n";
					}
				}
			}
		}
	}

	trace.flush();
	PIN_UnlockClient();
}

VOID InsInstrument(INS ins, VOID *v) {
	if (INS_IsControlFlow(ins)) {
		INS_InsertCall(
			ins,
			IPOINT_BEFORE, (AFUNPTR)TraceCall,
			IARG_INST_PTR,
			IARG_BRANCH_TARGET_ADDR,
			IARG_END
		);
	}
}

VOID Fini(INT32 code, VOID *v)
{
	trace << "#eof";
	trace.close();
}

INT32 Usage()
{
	PIN_ERROR("This Pintool application logs the cross module calls made by the specified module\n");
	return -1;
}

int main(int argc, char * argv[])
{

	PIN_InitSymbolsAlt(EXPORT_SYMBOLS);

	// Initialize pin
	if (PIN_Init(argc, argv)) {
		return Usage();
	}

	if (traceOutputFileName.Value().empty()) {
		trace.open("APItrace.out");
	}
	else {
		trace.open(traceOutputFileName.Value().c_str());
	}

	trace << "Section, RVA, API\n";

	if (!moduleNameToTrack.Value().empty()) {
		isMainModuleToTrack = 0;
		moduleToTrack = moduleNameToTrack.Value();
	}

	// Instrument each instruction
	INS_AddInstrumentFunction(InsInstrument, NULL);

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Register PIN exception Handler
	PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}
