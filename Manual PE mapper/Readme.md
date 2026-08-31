# 사용법

# 퀘이사 인 경우

본인의 Client.exe를 먼저 암호화해주세요
encrypt.exe Client.exe Client_xor.bin

그 후 

pe_loader_fixed_x64.exe file Client_xor.bin 이렇게 사용해주시면 됩니다.


# mimikatz 인 경우
Usage(ex) : pe_loader_fixed_x64.exe file mimikatz_exe.bin

file 그대로 입력해야 합니다
