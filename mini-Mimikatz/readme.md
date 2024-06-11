# readme

适合win10和win11版本

实现迷你版mimikatz，具体为用户提权、获取密钥、wdigest模块导出明文密码和msv模块导出哈希散列。

privilege.c 和 sekurlsa.c 文件为核心文件。

## 运行方法

1. 关掉windows defence
2. 在注册表中设置credentials为1
   - 在注册表  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProvider s\WDigest 子 键下新增一条新的数据项 UseLogonCredential，类型为 REG_DWORD，值为1，这将开启WDigest认证模块并在内存中缓存登录用户 的明文密码，随后重启计算机即可。

3. 关闭 credentials guard
   - 如果不使用虚拟机，请自行确保Credential Guard处于关闭状态，Credential Guard 处于开启状态下将无法从内存中获取密码散列（https://learn.microsoft.com/zh cn/windows/security/identity-protection/credential-guard/credential-guard manage#is-windows-defender-credential-guard-running） 

4. 以管理员身份运行visual studio，打开 Mimikatz-Learn.sln程序运行。