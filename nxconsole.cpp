// 该文件来自神秘的吃白饭的大鲸鱼
#include <windows.h>
#include <stdio.h>
#include <string>
#include <fcntl.h>
#include <io.h>

typedef void (*Py_InitializeEx_t)(int);
typedef int (*PyRun_SimpleString_t)(const char*);
typedef int (*Py_IsInitialized_t)();
typedef void* (*PyGILState_Ensure_t)();
typedef void (*PyGILState_Release_t)(void*);
typedef void (*PyErr_Print_t)();

DWORD WINAPI WorkerThread(LPVOID lpParam) {
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$", "r", stdin);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    printf("[DLL] Injected and started.\n");

    char dllPath[MAX_PATH];
    GetModuleFileNameA(GetModuleHandle(NULL), dllPath, MAX_PATH);
    std::string dllDir(dllPath);
    size_t lastSlash = dllDir.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        dllDir = dllDir.substr(0, lastSlash);
    }
    printf("[DLL] DLL directory: %s\n", dllDir.c_str());

    std::string scriptPath = dllDir + "\\cmdtxt1.py";
    printf("[DLL] Script path: %s\n", scriptPath.c_str());

    HMODULE hClient = GetModuleHandle(NULL);
    printf("[DLL] client.exe base address: 0x%p\n", hClient);

    Py_InitializeEx_t Py_InitializeEx = (Py_InitializeEx_t)GetProcAddress(hClient, "Py_InitializeEx");
    PyRun_SimpleString_t PyRun_SimpleString = (PyRun_SimpleString_t)GetProcAddress(hClient, "PyRun_SimpleString");
    Py_IsInitialized_t Py_IsInitialized = (Py_IsInitialized_t)GetProcAddress(hClient, "Py_IsInitialized");
    PyGILState_Ensure_t PyGILState_Ensure = (PyGILState_Ensure_t)GetProcAddress(hClient, "PyGILState_Ensure");
    PyGILState_Release_t PyGILState_Release = (PyGILState_Release_t)GetProcAddress(hClient, "PyGILState_Release");
    PyErr_Print_t PyErr_Print = (PyErr_Print_t)GetProcAddress(hClient, "PyErr_Print");

    if (!Py_InitializeEx || !PyRun_SimpleString || !Py_IsInitialized) {
        printf("[DLL] Failed to get Python functions.\n");
        system("pause");
        return 0;
    }

    printf("[DLL] Python functions found.\n");

    if (!Py_IsInitialized()) {
        printf("[DLL] Calling Py_InitializeEx(0)...\n");
        Py_InitializeEx(0);
        printf("[DLL] Py_InitializeEx(0) done.\n");
    }

    void* state = PyGILState_Ensure();
    printf("[DLL] GIL acquired.\n");

    // 执行 cmdtxt1.py 脚本（Python 2 兼容）
    char runScriptCode[2048];
    snprintf(runScriptCode, sizeof(runScriptCode),
        "import sys\n"
        "import os\n"
        "sys.stdout = open(r'%s\\py_output.txt', 'w')\n"
        "sys.stderr = sys.stdout\n"
        "print 'DLL directory:', r'%s'\n"
        "print 'Executing script from: %s'\n"
        "try:\n"
        "    with open(r'%s', 'r') as file:\n"
        "        exec(file.read())\n"
        "except Exception as e:\n"
        "    print 'Error:', e\n"
        "    import traceback\n"
        "    traceback.print_exc()\n"
        "print 'Script execution done'\n"
        "sys.stdout.flush()\n",
        dllDir.c_str(), dllDir.c_str(), scriptPath.c_str(), scriptPath.c_str());

    int res = PyRun_SimpleString(runScriptCode);
    printf("[DLL] PyRun_SimpleString for script returned: %d\n", res);
    if (res != 0 && PyErr_Print) {
        printf("[DLL] Printing error...\n");
        PyErr_Print();
    }

    // 启动 Python 2 交互控制台（直接使用 code.interact，避免自定义循环）
    const char* interactiveCode =
    "import sys\n"
    "import traceback\n"
    "\n"
    "sys.stdin = open('CONIN$', 'r')\n"
    "sys.stdout = open('CONOUT$', 'w', 1)   # 行缓冲\n"
    "sys.stderr = open('CONOUT$', 'w', 1)\n"
    "\n"
    "def my_interact():\n"
    "    buffer = []\n"
    "    sys.ps1 = '>>> '\n"
    "    sys.ps2 = '... '\n"
    "    while True:\n"
    "        try:\n"
    "            if buffer:\n"
    "                prompt = sys.ps2\n"
    "            else:\n"
    "                prompt = sys.ps1\n"
    "            sys.stdout.write(prompt)\n"
    "            sys.stdout.flush()\n"
    "            line = sys.stdin.readline()\n"
    "            if not line:\n"
    "                break\n"
    "            line = line.rstrip('\\n')\n"
    "            if line == 'exit()':\n"
    "                break\n"
    "            buffer.append(line)\n"
    "            source = '\\n'.join(buffer)\n"
    "            try:\n"
    "                code = compile(source, '<input>', 'single')\n"
    "                exec code\n"
    "                buffer = []\n"
    "            except SyntaxError as e:\n"
    "                if e.text is None and 'EOF' in str(e):\n"
    "                    continue\n"
    "                else:\n"
    "                    traceback.print_exc()\n"
    "                    buffer = []\n"
    "            except Exception as e:\n"
    "                traceback.print_exc()\n"
    "                buffer = []\n"
    "        except KeyboardInterrupt:\n"
    "            sys.stdout.write('KeyboardInterrupt\\n')\n"
    "            buffer = []\n"
    "        except EOFError:\n"
    "            break\n"
    "\n"
    "print 'Python interactive console ready.'\n"
    "my_interact()\n";

    printf("[DLL] Starting interactive Python console...\n");
    res = PyRun_SimpleString(interactiveCode);
    if (res != 0) {
        printf("[DLL] Interactive console exited with error.\n");
        if (PyErr_Print) PyErr_Print();
    }

    PyGILState_Release(state);
    printf("[DLL] GIL released.\n");

    printf("[DLL] Python console finished. Press any key to close this console...\n");
    system("pause > nul");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}