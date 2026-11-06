using System.Buffers;
using System.IO.Compression;
using ZstdSharp;
using ZstdSharp.Unsafe;

namespace TwoPassword.Core;

internal static class BlockCompression
{
    internal static int Encode(PackageCompression requested, ReadOnlySpan<byte> plaintext, Span<byte> scratch, ref Compressor? compressor, out byte codec)
    {
        codec = 0;
        if (requested == PackageCompression.None || plaintext.Length < 64) return plaintext.Length;
        bool success;
        int written;
        if (requested == PackageCompression.Brotli)
            success = BrotliEncoder.TryCompress(plaintext, scratch, out written, quality: 6, window: 20);
        else if (requested == PackageCompression.Zstd)
        {
            if (compressor is null)
            {
                compressor = new Compressor(3);
                compressor.SetParameter(ZSTD_cParameter.ZSTD_c_windowLog, 20);
                compressor.SetParameter(ZSTD_cParameter.ZSTD_c_checksumFlag, 1);
                compressor.SetParameter(ZSTD_cParameter.ZSTD_c_contentSizeFlag, 1);
            }
            success = compressor.TryWrap(plaintext, scratch, out written);
        }
        else throw new PackageException(Text.Get("不支持的块压缩算法。"));
        // Keeping an expanded result wastes space and creates larger parser bounds.
        if (!success || written >= plaintext.Length) return plaintext.Length;
        codec = (byte)requested;
        return written;
    }

    internal static void Decode(byte codec, ReadOnlySpan<byte> encoded, Span<byte> output, int expectedLength, ref Decompressor? decompressor)
    {
        if (codec == 0)
        {
            if (encoded.Length != expectedLength) throw new PackageException(Text.Get("原始块长度不匹配。"));
            encoded.CopyTo(output);
            return;
        }
        if (codec == (byte)PackageCompression.Brotli)
        {
            var decoder = new BrotliDecoder();
            try
            {
                var status = decoder.Decompress(encoded, output[..(expectedLength + 1)], out int consumed, out int written);
                if (status != OperationStatus.Done || consumed != encoded.Length || written != expectedLength)
                    throw new PackageException(Text.Get("Brotli 块被截断、包含尾随数据，或解压长度不匹配。"));
            }
            finally { decoder.Dispose(); }
            return;
        }
        if (codec == (byte)PackageCompression.Zstd)
        {
            ValidateZstdFrame(encoded, expectedLength);
            try
            {
                if (decompressor is null)
                {
                    decompressor = new Decompressor();
                    decompressor.SetParameter(ZSTD_dParameter.ZSTD_d_windowLogMax, 20);
                }
                // Caller owns this fixed-size buffer; never allocate from a frame-advertised size.
                int written = decompressor.Unwrap(encoded, output[..expectedLength]);
                if (written != expectedLength) throw new PackageException(Text.Get("Zstd 块解压长度不匹配。"));
            }
            catch (ZstdException e) { throw new PackageException(Text.Get("Zstd 压缩块无效。"), e); }
            return;
        }
        throw new PackageException(Text.Get("不支持的块压缩算法。"));
    }

    // The only unsafe application code pins bounded spans and calls the maintained Zstandard
    // parser. No pointer arithmetic, unmanaged allocation, or hand-written codec parser is used.
    private static unsafe void ValidateZstdFrame(ReadOnlySpan<byte> encoded, int expectedLength)
    {
        fixed (byte* pointer = encoded)
        {
            ZSTD_frameHeader header = default;
            nuint headerStatus = Methods.ZSTD_getFrameHeader(&header, pointer, (nuint)encoded.Length);
            if (headerStatus != 0 || header.frameType != ZSTD_frameType_e.ZSTD_frame ||
                header.dictID != 0 || header.windowSize > Envelope.ChunkSize ||
                header.frameContentSize != (ulong)expectedLength)
                throw new PackageException(Text.Get("Zstd 块头、字典、解压长度或窗口大小无效。"));
            nuint frameSize = Methods.ZSTD_findFrameCompressedSize(pointer, (nuint)encoded.Length);
            if (Methods.ZSTD_isError(frameSize) || frameSize != (nuint)encoded.Length)
                throw new PackageException(Text.Get("Zstd 块被截断，或包含额外压缩帧或尾随数据。"));
        }
    }
}
