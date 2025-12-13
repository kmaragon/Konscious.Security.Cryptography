namespace System.Diagnostics.CodeAnalysis
{
#if !NET6_0_OR_GREATER
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Property, Inherited = false, AllowMultiple = true)]
    internal sealed class MemberNotNullAttribute : Attribute
    {
#pragma warning disable CA1801 // Remove unused parameter
        public MemberNotNullAttribute(string member)
#pragma warning restore CA1801 // Remove unused parameter
        {
        }
    }
#endif
}
