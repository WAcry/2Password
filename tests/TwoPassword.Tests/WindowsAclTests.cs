using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;
using System.Security.Principal;
using TwoPassword.Core;

namespace TwoPassword.Tests;

internal static partial class Program
{
    private static async Task RunWindowsAclTests()
    {
        await Run("ACL capability policy rejects a filesystem without persistent ACLs", () => AclCheck(() =>
            AssertAclOperationalFailure(() => InvokeAclGuard("RequirePersistentAcls", 0u))));
        await Run("Named-stream support alone never substitutes for persistent ACL support", () => AclCheck(() =>
            AssertAclOperationalFailure(() => InvokeAclGuard("RequirePersistentAcls", 0x00040000u))));
        await Run("Persistent-ACL capability does not require named-stream capability", () => AclCheck(() =>
            InvokeAclGuard("RequirePersistentAcls", 0x00000008u)));
        await Run("Private directory blocks permissive parent ACLs and protects child files", PrivateDirectoryInheritance);
        await Run("Private directory creation preserves an existing directory, data, and ACL", PrivateDirectoryExisting);
        await Run("Private directory creation preserves an existing file", PrivateDirectoryExistingFile);
        await Run("Concurrent private-directory creation succeeds exactly once", PrivateDirectoryConcurrent);
        await Run("Private directory creation refuses a junction parent", PrivateDirectoryJunction);

        // Synthetic descriptor-only SID; no account or filesystem permissions are changed here.
        var user = new SecurityIdentifier("S-1-5-21-111111111-222222222-333333333-1001");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        const AceFlags inherit = AceFlags.ContainerInherit | AceFlags.ObjectInherit;
        const int full = (int)FileSystemRights.FullControl;
        GenericAce UserAce() => new CommonAce(inherit, AceQualifier.AccessAllowed, full, user, false, null);
        GenericAce SystemAce() => new CommonAce(inherit, AceQualifier.AccessAllowed, full, system, false, null);
        await Run("Exact protected current-user and SYSTEM DACL passes readback validation", () => AclCheck(() =>
            InvokeAclGuard("ValidateSecurity", AclFixture(user, [UserAce(), SystemAce()]), user)));

        var invalid = new (string Name, DirectorySecurity Security)[]
        {
            ("unprotected DACL", AclFixture(user, [UserAce(), SystemAce()], protect: false)),
            ("null DACL", AclFixture(user, null)),
            ("wrong owner", AclFixture(everyone, [UserAce(), SystemAce()])),
            ("extra Everyone grant", AclFixture(user, [UserAce(), SystemAce(),
                new CommonAce(inherit, AceQualifier.AccessAllowed, full, everyone, false, null)])),
            ("missing SYSTEM grant", AclFixture(user, [UserAce()])),
            ("duplicate user in place of SYSTEM", AclFixture(user, [UserAce(), UserAce()])),
            ("read-only user grant", AclFixture(user,
                [new CommonAce(inherit, AceQualifier.AccessAllowed, (int)FileSystemRights.Read, user, false, null), SystemAce()])),
            ("deny ACE", AclFixture(user,
                [new CommonAce(inherit, AceQualifier.AccessDenied, full, user, false, null), SystemAce()])),
            ("non-inheriting ACE", AclFixture(user,
                [new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, full, user, false, null), SystemAce()])),
            ("inherit-only ACE", AclFixture(user,
                [new CommonAce(inherit | AceFlags.InheritOnly, AceQualifier.AccessAllowed, full, user, false, null), SystemAce()])),
            ("inherited ACE", AclFixture(user,
                [new CommonAce(inherit | AceFlags.Inherited, AceQualifier.AccessAllowed, full, user, false, null), SystemAce()])),
            ("callback ACE", AclFixture(user,
                [new CommonAce(inherit, AceQualifier.AccessAllowed, full, user, true, null), SystemAce()])),
            ("object-specific ACE", AclFixture(user,
                [new ObjectAce(inherit, AceQualifier.AccessAllowed, full, user, ObjectAceFlags.None,
                    Guid.Empty, Guid.Empty, false, null), SystemAce()]))
        };
        foreach (var item in invalid)
            await Run("Private-directory ACL readback rejects " + item.Name, () => AclCheck(() =>
                AssertAclOperationalFailure(() => InvokeAclGuard("ValidateSecurity", item.Security, user))));
    }

    private static Task AclCheck(Action action)
    {
        action();
        return Task.CompletedTask;
    }

    private static void InvokeAclGuard(string name, params object?[] arguments)
    {
        MethodInfo method = typeof(WindowsPrivateDirectory).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Expected production ACL guard is missing: " + name);
        try { method.Invoke(null, arguments); }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
        }
    }

    private static void AssertAclOperationalFailure(Action action)
    {
        Exception? failure = null;
        try { action(); }
        catch (Exception error) { failure = error; }
        Assert(failure is IOException and not PackageException,
            "Unsafe ACL/capability must raise an operational IOException, not a package-damage signal: " + failure);
    }

    private static DirectorySecurity AclFixture(SecurityIdentifier owner, GenericAce[]? aces, bool protect = true)
    {
        RawAcl? acl = null;
        if (aces is not null)
        {
            acl = new RawAcl(GenericAcl.AclRevisionDS, aces.Length);
            foreach (GenericAce ace in aces) acl.InsertAce(acl.Count, ace);
        }
        var flags = ControlFlags.DiscretionaryAclPresent;
        if (protect) flags |= ControlFlags.DiscretionaryAclProtected;
        var raw = new RawSecurityDescriptor(flags, owner, owner, null, acl);
        byte[] bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorBinaryForm(bytes);
        return security;
    }

    private static Task PrivateDirectoryInheritance()
    {
        string parent = Path.Combine(_root, "acl-permissive-parent");
        Directory.CreateDirectory(parent);
        using var identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User!;
        var parentSecurity = new DirectorySecurity();
        parentSecurity.SetOwner(user);
        parentSecurity.SetAccessRuleProtection(true, false);
        foreach (SecurityIdentifier sid in new[]
        {
            user,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.WorldSid, null)
        })
            parentSecurity.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(parent), parentSecurity);
        string path = Path.Combine(parent, "私有-بالعربية-日本語");
        WindowsPrivateDirectory.Create(path);
        AssertPrivateAcl(new DirectoryInfo(path), user, root: true);
        string child = Path.Combine(path, "child");
        Directory.CreateDirectory(child);
        string file = Path.Combine(child, "synthetic-plaintext.txt");
        File.WriteAllText(file, "Synthetic plaintext must inherit only private access.");
        AssertPrivateAcl(new DirectoryInfo(child), user, root: false);
        AssertPrivateAcl(new FileInfo(file), user, root: false);
        return Task.CompletedTask;
    }

    private static void AssertPrivateAcl(FileSystemInfo info, SecurityIdentifier user, bool root)
    {
        FileSystemSecurity security = info is DirectoryInfo directory
            ? FileSystemAclExtensions.GetAccessControl(directory, AccessControlSections.Access | AccessControlSections.Owner)
            : FileSystemAclExtensions.GetAccessControl((FileInfo)info, AccessControlSections.Access | AccessControlSections.Owner);
        var raw = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        var permitted = new HashSet<string>(StringComparer.Ordinal)
        {
            user.Value, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value
        };
        Assert(raw.DiscretionaryAcl is not null && raw.DiscretionaryAcl.Count == permitted.Count,
            "Private path has a null, missing, or extra access rule: " + info.Name);
        Assert((raw.ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0, "DACL is not present.");
        if (root)
        {
            Assert(raw.Owner is not null && user.Equals(raw.Owner),
                "Private staging root owner is not the creating user.");
            Assert((raw.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0,
                "Private root permits inherited access from its parent.");
        }
        // Child ownership follows the Windows token's default owner (which can
        // be Administrators in an elevated process). Its DACL must still grant
        // access only to the two intended principals; owner equality is the
        // helper's explicit guarantee for the private staging root.
        foreach (GenericAce ace in raw.DiscretionaryAcl!)
        {
            Assert(ace is CommonAce, "Unexpected access-control entry type.");
            var common = (CommonAce)ace;
            Assert(!common.IsCallback && common.AceQualifier == AceQualifier.AccessAllowed &&
                   common.AccessMask == (int)FileSystemRights.FullControl &&
                   permitted.Remove(common.SecurityIdentifier.Value),
                   "Private path grants unexpected access: " + info.Name);
            if (root)
                Assert(common.AceFlags == (AceFlags.ObjectInherit | AceFlags.ContainerInherit),
                    "Private root ACL does not protect both child files and directories.");
            else
                Assert((common.AceFlags & AceFlags.Inherited) != 0 &&
                       (common.AceFlags & AceFlags.InheritOnly) == 0,
                    "Child ACL does not grant the inherited permission on the child itself.");
        }
        Assert(permitted.Count == 0, "Required private principals are missing.");
    }

    private static async Task PrivateDirectoryExisting()
    {
        string path = Path.Combine(_root, "acl-existing-directory");
        Directory.CreateDirectory(path);
        string sentinel = Path.Combine(path, "preserve.txt");
        File.WriteAllText(sentinel, "Existing synthetic user data must survive.");
        var before = FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(path),
            AccessControlSections.Access | AccessControlSections.Owner).GetSecurityDescriptorBinaryForm();
        await MustFail(() => AclCheck(() => WindowsPrivateDirectory.Create(path)));
        var after = FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(path),
            AccessControlSections.Access | AccessControlSections.Owner).GetSecurityDescriptorBinaryForm();
        Assert(before.SequenceEqual(after), "Existing directory ACL was modified.");
        Assert(File.ReadAllText(sentinel) == "Existing synthetic user data must survive." &&
               Directory.EnumerateFileSystemEntries(path).Count() == 1, "Existing directory data changed.");
    }

    private static async Task PrivateDirectoryExistingFile()
    {
        string path = Path.Combine(_root, "acl-existing-file.txt");
        File.WriteAllText(path, "Existing file must not be replaced by a directory.");
        await MustFail(() => AclCheck(() => WindowsPrivateDirectory.Create(path)));
        Assert(File.ReadAllText(path) == "Existing file must not be replaced by a directory." &&
               !Directory.Exists(path), "Existing file was replaced.");
    }

    private static async Task PrivateDirectoryConcurrent()
    {
        string path = Path.Combine(_root, "acl-concurrent-directory");
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var attempts = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            await start.Task;
            try { WindowsPrivateDirectory.Create(path); return (Exception?)null; }
            catch (Exception error) { return error; }
        })).ToArray();
        start.SetResult();
        Exception?[] results = await Task.WhenAll(attempts);
        Assert(results.Count(error => error is null) == 1, "Creation did not succeed exactly once.");
        Assert(results.All(error => error is null or IOException), "Unexpected failure during atomic creation.");
        using var identity = WindowsIdentity.GetCurrent();
        AssertPrivateAcl(new DirectoryInfo(path), identity.User!, root: true);
        Assert(!Directory.EnumerateFileSystemEntries(path).Any(), "Concurrent creation left unexpected content.");
    }

    private static async Task PrivateDirectoryJunction()
    {
        string target = Path.Combine(_root, "acl-junction-target");
        string link = Path.Combine(_root, "acl-junction-parent");
        Directory.CreateDirectory(target);
        CreateJunction(link, target);
        await MustFail(() => AclCheck(() => WindowsPrivateDirectory.Create(Path.Combine(link, "must-not-create"))));
        Assert(!Directory.EnumerateFileSystemEntries(target).Any(), "Private directory followed a junction.");
    }
}
