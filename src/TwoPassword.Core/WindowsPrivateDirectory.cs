using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace TwoPassword.Core;

/// <summary>Creates a new Windows directory only when its private, inheritable DACL can be verified.</summary>
public static class WindowsPrivateDirectory
{
    /// <summary>Requires a new path on an ACL-capable volume. Existing directories are never reused.</summary>
    public static void Create(string path)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(Text.Get("创建私有工作目录需要 Windows。"));

        string full = SafePaths.Full(path);
        SafePaths.EnsureDestination(full);
        string parent = Path.GetDirectoryName(full)!;
        RequirePersistentAcls(WindowsFileSystemCapabilities.Query(parent));
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User
            ?? throw new IOException(Text.Get("无法确定当前 Windows 用户。"));
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new DirectorySecurity();
        security.SetOwner(user);
        security.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { user, system })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));

        string extended = SafePaths.Extended(full);
        bool created = false, verified = false;
        try
        {
            // Unlike DirectoryInfo.Create, Win32 CreateDirectory fails if the name already exists.
            // Supply the DACL at creation; no unprotected directory is opened for a later ACL update.
            byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
            unsafe
            {
                fixed (byte* pointer = descriptor)
                {
                    var attributes = new SecurityAttributes
                    {
                        Length = Marshal.SizeOf<SecurityAttributes>(),
                        SecurityDescriptor = (IntPtr)pointer,
                        InheritHandle = 0
                    };
                    if (!CreateDirectoryW(extended, ref attributes))
                    {
                        int error = Marshal.GetLastWin32Error();
                        throw new IOException(Text.Get("无法创建私有工作目录：{0} (Windows {1})", full, error),
                            new Win32Exception(error));
                    }
                    created = true;
                }
            }

            SafePaths.EnsureNoReparseAncestors(full, true);
            DirectorySecurity actual;
            try
            {
                actual = FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(extended),
                    AccessControlSections.Access | AccessControlSections.Owner);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                throw new IOException(Text.Get("无法验证私有工作目录的访问权限，已停止操作：{0}", full), error);
            }
            ValidateSecurity(actual, user);
            verified = true;
        }
        finally
        {
            if (created && !verified)
            {
                // This helper has not written any files. Never recursively remove an unexpected tree.
                try { Directory.Delete(extended, recursive: false); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    internal static void RequirePersistentAcls(uint capabilities)
    {
        if ((capabilities & WindowsFileSystemCapabilities.PersistentAcls) == 0)
            throw new IOException(Text.Get("目标文件系统不支持持久访问控制列表（ACL）。请将解包或恢复工作区放在本地 NTFS 磁盘。"));
    }

    [SupportedOSPlatform("windows")]
    internal static void ValidateSecurity(DirectorySecurity security, SecurityIdentifier user)
    {
        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            user.Value,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value
        };
        const ControlFlags required = ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected;
        if ((descriptor.ControlFlags & required) != required || descriptor.Owner is null || !user.Equals(descriptor.Owner) ||
            descriptor.DiscretionaryAcl is null || descriptor.DiscretionaryAcl.Count != expected.Count)
            throw InvalidSecurity();

        // Inspect the raw ACL so that unknown/object/callback ACEs cannot be hidden by rule filtering.
        foreach (GenericAce ace in descriptor.DiscretionaryAcl)
        {
            if (ace is not CommonAce rule || rule.IsCallback || rule.AceQualifier != AceQualifier.AccessAllowed ||
                rule.AceFlags != (AceFlags.ContainerInherit | AceFlags.ObjectInherit) ||
                rule.AccessMask != (int)FileSystemRights.FullControl || !expected.Remove(rule.SecurityIdentifier.Value))
                throw InvalidSecurity();
        }
        if (expected.Count != 0) throw InvalidSecurity();
    }

    private static IOException InvalidSecurity() =>
        new(Text.Get("无法确认工作目录只允许当前用户和 SYSTEM 访问，已停止操作。"));

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);
}

internal static class WindowsFileSystemCapabilities
{
    internal const uint PersistentAcls = 0x00000008;
    internal const uint NamedStreams = 0x00040000;

    internal static uint Query(string existingPath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(Text.Get("查询文件系统能力需要 Windows。"));

        // Query the actual volume behind an existing handle, not a drive-letter or filesystem-name guess.
        // A server that cannot report these capabilities is rejected; unsupported is never assumed safe.
        using var handle = CreateFileW(SafePaths.Extended(existingPath), 0,
            FileShare.Read | FileShare.Write | FileShare.Delete, IntPtr.Zero, 3,
            0x02000000 | 0x00200000, IntPtr.Zero); // BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            throw QueryFailed(existingPath, error);
        }
        if (!GetVolumeInformationByHandleW(handle, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero,
            out uint flags, IntPtr.Zero, 0))
        {
            int error = Marshal.GetLastWin32Error();
            throw QueryFailed(existingPath, error);
        }
        return flags;
    }

    private static IOException QueryFailed(string path, int error) =>
        new(Text.Get("无法查询文件系统能力，已停止操作：{0} (Windows {1})", path, error), new Win32Exception(error));

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint desiredAccess, FileShare shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle file, IntPtr volumeName,
        uint volumeNameSize, IntPtr volumeSerial, IntPtr maximumComponentLength, out uint fileSystemFlags,
        IntPtr fileSystemName, uint fileSystemNameSize);
}
