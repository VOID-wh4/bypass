using System;

internal static class ManagedEntry
{
    private static int Main()
    {
        int value = System.Diagnostics.Process.GetCurrentProcess().Id;
        return (value & 0x7fff) + 1000;
    }
}
