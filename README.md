# Thread-Hijacking

Thread Execution Hijacking is commonly performed by suspending an existing process then unmapping/hollowing its memory,
which can then be replaced with malicious code or the path to a DLL. A handle to an existing victim process is first created with native Windows API calls such as OpenThread.
At this point the process can be suspended then written to, realigned to the injected code, and resumed via SuspendThread , VirtualAllocEx, WriteProcessMemory, 
SetThreadContext, then ResumeThread respectively.

# TECHNICAL DETAILS
* Open a handle targetProcessHandle to the process that we want to inject using OpenProcess
* Allocate some executable memory ExecBuffer in the target process with VirtualAllocEx
* Write shellcode we want to inject into the memory ExecBuffer, using WriteProcessMemory
* Find a thread ID of the thread we want to hijack in the target process. In our case, we will fetch the thread ID of the first thread in our target process.
* Suspend the target thread - the thread we want to hijack (threadHijacked) with SuspendThread
* Retrieve the target thread's context with GetThreadContext
* Update the target thread's instruction pointer (in my case x86 EIP register / x64 RIP) to point to the shellcode, which was written into the target process's memory using WriteProcessMemory
* Commit the hijacked thread's new context with SetThreadContext
* Resume the hijacked thread with ResumeThread
</br>
<p align="center">
  <img src="https://github.com/ZeroM3m0ry/Thread-Hijacking/blob/master/th.gif" />
</p>
