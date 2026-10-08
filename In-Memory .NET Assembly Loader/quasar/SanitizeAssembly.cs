using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

internal static class SanitizeAssembly
{
    // ConfuserEx 1.x 처리와 충돌하는 컴파일러 생성 특성만 제거한다.
    // 코드, 형식/메서드 이름, 리소스와 네트워크 설정은 이 단계에서 변경하지 않는다.
    private static readonly HashSet<string> RemovableAttributes = new HashSet<string>(StringComparer.Ordinal)
    {
        "System.Runtime.CompilerServices.IteratorStateMachineAttribute",
        "System.Runtime.CompilerServices.AsyncStateMachineAttribute",
        "System.Diagnostics.DebuggerHiddenAttribute",
        "System.Diagnostics.DebuggerStepThroughAttribute"
    };

    private static int Main(string[] args)
    {
        try
        {
            return Run(args);
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.GetType().FullName);
            try { Console.Error.WriteLine(error.Message); } catch { }
            return 1;
        }
    }

    private static int Run(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("Usage: SanitizeAssembly <input> <output>");
            return 2;
        }

        Console.WriteLine("Loading module");
        // 원본을 덮어쓰지 않고 지정한 출력 경로에 정리된 복사본을 기록한다.
        ModuleDefMD module = ModuleDefMD.Load(args[0]);
        int removed = 0;
        removed += Remove(module.CustomAttributes);

        // 어셈블리뿐 아니라 형식과 각 멤버에 붙은 대상 특성도 모두 확인한다.
        foreach (TypeDef type in module.GetTypes())
        {
            removed += Remove(type.CustomAttributes);
            foreach (MethodDef method in type.Methods)
            {
                removed += Remove(method.CustomAttributes);
                foreach (ParamDef parameter in method.ParamDefs)
                    removed += Remove(parameter.CustomAttributes);
            }
            foreach (FieldDef field in type.Fields)
                removed += Remove(field.CustomAttributes);
            foreach (PropertyDef property in type.Properties)
                removed += Remove(property.CustomAttributes);
            foreach (EventDef eventDefinition in type.Events)
                removed += Remove(eventDefinition.CustomAttributes);
        }

        Console.WriteLine("Writing module");
        ModuleWriterOptions options = new ModuleWriterOptions(module);
        options.Logger = DummyLogger.NoThrowInstance;
        module.Write(args[1], options);
        Console.WriteLine("Removed attributes: " + removed);
        return 0;
    }

    private static int Remove(CustomAttributeCollection attributes)
    {
        int removed = 0;
        for (int index = attributes.Count - 1; index >= 0; index--)
        {
            if (RemovableAttributes.Contains(attributes[index].AttributeType.FullName))
            {
                attributes.RemoveAt(index);
                removed++;
            }
        }
        return removed;
    }
}
