# TraceAPI
TraceAPI logs the Windows API calls and calls to runtime generated code for a given executable. Additionally one can log some specific module calls inside the given executable provided the module name is specified in **lowercase with/without the extension** on the command-line. 

You can also specify the name for the output log file. If no name is specified default name "APItrace.out" is used.

### Usage:

pin.exe -t TraceAPI.dll [-m "ModuleName"] [-o "OutputFileName"] -- [executable] [arguments]

**Example command-line for "exe":**

pin.exe -t TraceAPI.dll -o "TraceLog.out" -- Test.exe

**Example command-line for "dll":**

pin.exe -t TraceAPI.dll -m "somedll" -o "ModuleTraceLog.out" -- regsvr32.exe SomeDll.dll

### Sample Output:
```
Section, RVA, API
.text, 0xe6050, kernel32.IsProcessorFeaturePresent+0
.text, 0x5794f, kernel32.LoadLibraryExW+0
.text, 0x57929, kernel32.GetProcAddress+0
.text, 0x57b4f, KernelBase.InitializeCriticalSectionEx+0
.text, 0x5794f, kernel32.LoadLibraryExW+0
.text, 0x57929, kernel32.GetProcAddress+0
.text, 0x579f7, KernelBase.FlsAlloc+0
.text, 0x57929, kernel32.GetProcAddress+0
.text, 0x57aeb, KernelBase.FlsSetValue+0
.text, 0xb0211, kernel32.LoadLibraryExW+0
.text, 0xb01db, kernel32.GetProcAddress+0
.text, 0xb09b1, KernelBase.InitializeCriticalSectionEx+0
```

### Build steps:
1. Download [Intel PIN](https://software.intel.com/content/www/us/en/develop/articles/pin-a-binary-instrumentation-tool-downloads.html) [Intel Pin 3.16 was used while creating this tool]
2. Create a folder with the name TraceAPI inside %pin_root_dir%\source\tools
3. Put the files from the project inside above created folder
4. Open the project with Visual Studio [Visual Studio 2017 was used while creating this tool]
5. Compile the project by selecting Release|x32
