# DetectNtoskrnlIntegrity
[dejavu-secure(既视感安全实验室)](https://www.dejavu-secure.com/)
https://bbs.kanxue.com/thread-286152.htm

Windows Kernel Security: Memory Integrity Verification with Disk Verification of ntoskrnl.exe
Windows内核安全: 与磁盘校验 ntoskrnl.exe 的内存完整性

Test on Windows 11 23H2 (Microsoft Windows Version 10.0.22631.5039)
测试于 Windows 11 23H2 (Microsoft Windows 版本 10.0.22631.5039)

This paper analyzes memory integrity verification methods for ntoskrnl.exe in the Windows kernel by comparing memory and disk versions to detect malicious tampering. The article examines technical details that need attention during integrity verification processes and proposes a complete verification workflow. It deeply explores solutions to challenges posed by SSDT data compression, page table randomization, and Retpoline technology on verification, providing effective safeguards for kernel program security.

本文解析了对Windows内核中ntoskrnl.exe的内存完整性校验方法，通过对比内存与磁盘版本来检测恶意篡改。文章分析在检测完整性过程中需要注意的技术细节，提出了完整的校验流程，深入探讨了如何解决SSDT数据压缩，页表随机化和Retpoline技术对校验的影响和解决方案，为内核程序运行的安全提供了有效保障。
