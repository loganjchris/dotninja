using System;
using System.Runtime.InteropServices;

namespace DotNinjaFixture;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct PackedRecord
{
    public byte Tag;
    public int Value;
    public static int StaticValue = 7;
}

public static class Program
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string name);

    public static string Decrypt(int key)
    {
        char[] value = { (char)('o' ^ key), (char)('k' ^ key) };
        for (int i = 0; i < value.Length; i++) value[i] = (char)(value[i] ^ key);
        return new string(value);
    }

    public static int SwitchAndJoin(int value)
    {
        int result;
        switch (value) { case 0: result = 10; break; case 1: result = 20; break; default: result = 30; break; }
        try { if ((value * 0) == 0) result += 1; }
        catch (Exception) { result = -1; }
        finally { result += 2; }
        return result;
    }

    public static int Main()
    {
        Console.WriteLine(Decrypt(9));
        _ = GetModuleHandleW("kernel32.dll");
        return SwitchAndJoin(1);
    }
}
