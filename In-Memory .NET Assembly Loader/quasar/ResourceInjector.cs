using System;
using System.IO;
using System.Runtime.InteropServices;

internal static class ResourceInjector
{
    // Win32 리소스 갱신 API를 사용해 이미 컴파일된 외부 loader에 데이터를 추가한다.
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr BeginUpdateResource(string fileName, bool deleteExistingResources);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateResource(IntPtr update, IntPtr type, IntPtr name,
        ushort language, byte[] data, uint dataSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EndUpdateResource(IntPtr update, bool discard);

    private static int Main(string[] args)
    {
        if (args.Length != 2)
            return 2;
        string executable = Path.GetFullPath(args[0]);
        // 두 번째 인수는 Build-Loader.ps1이 만든 AES 암호문(package.bin)이다.
        byte[] data = File.ReadAllBytes(args[1]);
        IntPtr update = BeginUpdateResource(executable, false);
        if (update == IntPtr.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        bool committed = false;
        try
        {
            // type 10은 RT_RCDATA, name 101은 LoaderStub이 조회하는 고정 리소스 ID다.
            if (!UpdateResource(update, (IntPtr)10, (IntPtr)101, 0, data, (uint)data.Length))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            if (!EndUpdateResource(update, false))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            committed = true;
        }
        finally
        {
            if (!committed)
                EndUpdateResource(update, true);
            // 빌드 도구 프로세스에서도 암호문 버퍼를 사용 후 정리한다.
            Array.Clear(data, 0, data.Length);
        }
        return 0;
    }
}
