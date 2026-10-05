# 설명

로더에 섹션을 추가하는 코드를 작성하여 메모리 할당없이 진행하는 기법

## Section.exe 의 경우
해당 로더는 도넛 쉘코드가 작동하게끔 만들었습니다.

그 결과 비트 디펜더 제외하고 다 탐지가 안됐습니다.

Section.exe mimikatz_donut.bin

## Section_hsf.exe 의 경우
compress_helper로 PeBinForge로 생성된 mimikatz 쉘코드를 압축한 뒤 MAC 암호화로 실행되는 원리입니다.
여기서 PeBinForge의 헤더 스톰프 기능을 추가한 쉘코드를 이용하기 때문에 비트디펜더를 우회할 수 있었습니다.

Section_hsf1.exe mimikatz.bin
