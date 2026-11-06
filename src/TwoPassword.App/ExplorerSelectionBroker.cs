using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace TwoPassword.App;

/// <summary>
/// Joins Explorer's per-item process launches without forwarding ordinary application launches.
/// The pipe is scoped to this copy, Windows user, logon session and elevation level. It carries
/// only selected paths, never passwords. A sender exits only after the window has accepted them.
/// </summary>
internal sealed class ExplorerSelectionBroker : IDisposable
{
    private const int MaximumMessageBytes = 1024 * 1024;
    private readonly NamedPipeServerStream _server;
    private readonly CancellationTokenSource _stop = new();
    private Task? _listener;
    private bool _disposed;

    private ExplorerSelectionBroker(NamedPipeServerStream server) => _server = server;

    internal static string PipeName(string executable, bool elevated)
    {
        using var identity = WindowsIdentity.GetCurrent();
        using var process = Process.GetCurrentProcess();
        var scope = string.Join('\n', Path.GetFullPath(executable).ToUpperInvariant(), identity.User?.Value,
            process.SessionId.ToString(System.Globalization.CultureInfo.InvariantCulture), elevated.ToString());
        return "2Password.Explorer." + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(scope)));
    }

    /// <returns>A new owner, or null after an existing owner acknowledged the selection.</returns>
    internal static async Task<ExplorerSelectionBroker?> ConnectOrCreateAsync(string pipeName, IReadOnlyList<string> paths)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(paths);
        if (payload.Length > MaximumMessageBytes) throw new ArgumentException("Explorer selection is too large.", nameof(paths));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        while (true)
        {
            timeout.Token.ThrowIfCancellationRequested();
            try
            {
                return new ExplorerSelectionBroker(new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance));
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // A different Explorer launch won the race, or its previous owner is closing.
            }
            try
            {
                using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await client.ConnectAsync(500, timeout.Token).ConfigureAwait(false);
                var header = new byte[4];
                BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
                await client.WriteAsync(header, timeout.Token).ConfigureAwait(false);
                await client.WriteAsync(payload, timeout.Token).ConfigureAwait(false);
                await client.FlushAsync(timeout.Token).ConfigureAwait(false);
                var acknowledgement = new byte[1];
                await client.ReadExactlyAsync(acknowledgement, timeout.Token).ConfigureAwait(false);
                if (acknowledgement[0] == 1) return null;
                throw new IOException("The Explorer selection was not accepted.");
            }
            catch (Exception error) when (error is IOException or TimeoutException or UnauthorizedAccessException)
            {
                await Task.Delay(50, timeout.Token).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Start only after the initial window is ready; earlier clients wait for an acknowledgement.</summary>
    internal void StartReceiving(Func<string[], Task> receive)
    {
        if (_listener is not null) throw new InvalidOperationException("The Explorer receiver is already running.");
        var token = _stop.Token;
        _listener = Task.Run(() => ListenAsync(receive, token), token);
    }

    private async Task ListenAsync(Func<string[], Task> receive, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await _server.WaitForConnectionAsync(token).ConfigureAwait(false);
                // A stalled or malformed client must not block all later Explorer selections.
                using var requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                requestTimeout.CancelAfter(TimeSpan.FromSeconds(10));
                var header = new byte[4];
                await _server.ReadExactlyAsync(header, requestTimeout.Token).ConfigureAwait(false);
                var length = BinaryPrimitives.ReadInt32LittleEndian(header);
                if (length is <= 0 or > MaximumMessageBytes) continue;
                var payload = new byte[length];
                await _server.ReadExactlyAsync(payload, requestTimeout.Token).ConfigureAwait(false);
                var paths = JsonSerializer.Deserialize<string[]>(payload);
                if (paths is null || paths.Length is 0 or > 4096 ||
                    paths.Any(path => string.IsNullOrWhiteSpace(path) || path.Length > 32767)) continue;
                await receive(paths).ConfigureAwait(false);
                await _server.WriteAsync(new byte[] { 1 }, requestTimeout.Token).ConfigureAwait(false);
                await _server.FlushAsync(requestTimeout.Token).ConfigureAwait(false);
            }
            catch (Exception error) when (error is IOException or JsonException or OperationCanceledException or ObjectDisposedException)
            {
                if (token.IsCancellationRequested) return;
            }
            finally
            {
                if (!token.IsCancellationRequested && _server.IsConnected)
                {
                    try { _server.Disconnect(); }
                    catch (IOException) { }
                }
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _stop.Cancel();
        _server.Dispose();
        _stop.Dispose();
    }
}
