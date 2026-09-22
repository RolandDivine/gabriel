using System;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GabrielApp;

/// <summary>
/// P/Invoke bindings to gabriel_ffi.dll (the Rust core's C ABI).
///
/// Ownership rule, which the whole file exists to enforce in one place:
/// every string the Rust side returns was allocated by Rust and must go
/// back to gabriel_free_string. C# never frees Rust memory itself. So no
/// binding below returns a string directly to callers -- each one copies
/// the bytes into a managed string and frees the original immediately,
/// which is why the raw entry points return IntPtr rather than string.
/// (Marshalling straight to string would leak, because the marshaller
/// would copy it and then nobody would ever free the Rust allocation.)
/// </summary>
internal static class GabrielNative
{
    private const string Dll = "gabriel_ffi";

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr gabriel_start(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string dataDir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string displayName);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void gabriel_stop(IntPtr node);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr gabriel_device_id(IntPtr node);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int gabriel_neighbor_count(IntPtr node);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr gabriel_peers_json(IntPtr node);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int gabriel_send_message(
        IntPtr node,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string destinationHex,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string text);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr gabriel_take_inbox_json(IntPtr node);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void gabriel_free_string(IntPtr ptr);

    /// <summary>Copies a Rust-owned string into managed memory and frees the original.</summary>
    private static string? TakeString(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            return Marshal.PtrToStringUTF8(ptr);
        }
        finally
        {
            gabriel_free_string(ptr);
        }
    }

    public static IntPtr Start(string dataDir, string displayName) => gabriel_start(dataDir, displayName);

    public static void Stop(IntPtr node) => gabriel_stop(node);

    public static string DeviceId(IntPtr node) => TakeString(gabriel_device_id(node)) ?? "(unavailable)";

    public static int NeighborCount(IntPtr node) => gabriel_neighbor_count(node);

    public static int SendMessage(IntPtr node, string destinationHex, string text) =>
        gabriel_send_message(node, destinationHex, text);

    public static IReadOnlyList<PeerView> Peers(IntPtr node)
    {
        var json = TakeString(gabriel_peers_json(node));
        if (string.IsNullOrEmpty(json))
        {
            return Array.Empty<PeerView>();
        }
        return JsonSerializer.Deserialize<List<PeerView>>(json) ?? new List<PeerView>();
    }

    public static IReadOnlyList<InboxMessage> TakeInbox(IntPtr node)
    {
        var json = TakeString(gabriel_take_inbox_json(node));
        if (string.IsNullOrEmpty(json))
        {
            return Array.Empty<InboxMessage>();
        }
        return JsonSerializer.Deserialize<List<InboxMessage>>(json) ?? new List<InboxMessage>();
    }
}

internal sealed class PeerView
{
    [JsonPropertyName("device_id")] public string DeviceId { get; set; } = "";
    [JsonPropertyName("display_name")] public string DisplayName { get; set; } = "";
    [JsonPropertyName("address")] public string Address { get; set; } = "";
    [JsonPropertyName("offers_gateway")] public bool OffersGateway { get; set; }
    [JsonPropertyName("routable")] public bool Routable { get; set; }
    [JsonPropertyName("last_seen_secs")] public float LastSeenSecs { get; set; }

    /// <summary>What the peer list shows for each row.</summary>
    public string Summary
    {
        get
        {
            var tags = "";
            if (OffersGateway) tags += "  [gateway]";
            if (!Routable) tags += "  [no mesh listener]";
            return $"{DisplayName}{tags}";
        }
    }

    public string Details => $"{ShortId}  ·  {Address}  ·  seen {LastSeenSecs:0.0}s ago";

    public string ShortId => DeviceId.Length >= 12 ? DeviceId[..12] + "…" : DeviceId;
}

internal sealed class InboxMessage
{
    [JsonPropertyName("from")] public string From { get; set; } = "";
    [JsonPropertyName("text")] public string Text { get; set; } = "";
    [JsonPropertyName("received_unix")] public long ReceivedUnix { get; set; }

    public string ShortFrom => From.Length >= 12 ? From[..12] + "…" : From;

    public string Timestamp =>
        DateTimeOffset.FromUnixTimeSeconds(ReceivedUnix).ToLocalTime().ToString("HH:mm:ss");
}
