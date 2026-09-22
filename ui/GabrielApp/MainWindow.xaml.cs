using System;
using System.Collections.ObjectModel;
using System.Linq;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Input;
using Windows.System;

namespace GabrielApp;

/// <summary>
/// One row in the message list. Covers both directions, so a sent message
/// and a received one sit in the same timeline.
/// </summary>
internal sealed class MessageEntry
{
    public string Header { get; init; } = "";
    public string Text { get; init; } = "";

    public static MessageEntry Received(InboxMessage msg) => new()
    {
        Header = $"{msg.Timestamp}  ·  from {msg.ShortFrom}",
        Text = msg.Text,
    };

    public static MessageEntry Sent(string toShortId, string text, int neighborsReached)
    {
        // Worth surfacing honestly: 0 neighbours means it went to the
        // outbox, not out on the wire. The user should know the difference
        // between "sent" and "queued".
        var status = neighborsReached > 0
            ? $"sent to {neighborsReached} neighbour(s)"
            : "queued — no peers reachable yet, will retry";
        return new MessageEntry
        {
            Header = $"{DateTime.Now:HH:mm:ss}  ·  to {toShortId}  ·  {status}",
            Text = text,
        };
    }

    public static MessageEntry Notice(string text) => new()
    {
        Header = $"{DateTime.Now:HH:mm:ss}  ·  system",
        Text = text,
    };
}

public sealed partial class MainWindow : Window
{
    private IntPtr _node = IntPtr.Zero;
    private readonly DispatcherQueueTimer _timer;
    private readonly ObservableCollection<PeerView> _peers = new();
    private readonly ObservableCollection<MessageEntry> _messages = new();
    private string _deviceId = "";

    public MainWindow()
    {
        InitializeComponent();
        Title = "Gabriel";

        PeerList.ItemsSource = _peers;
        MessageList.ItemsSource = _messages;
        RecipientBox.ItemsSource = _peers;

        StartNode();

        // Poll the core for peers and new messages. The core is async
        // Rust; this is the UI thread. Polling a couple of times a second
        // is plenty for a peer list that changes on a 5s beacon, and it
        // avoids marshalling callbacks from Rust threads into the UI.
        _timer = DispatcherQueue.CreateTimer();
        _timer.Interval = TimeSpan.FromMilliseconds(750);
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();

        Closed += (_, _) => Shutdown();
    }

    private void StartNode()
    {
        var dataDir = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Gabriel");

        _node = GabrielNative.Start(dataDir, Environment.MachineName);

        if (_node == IntPtr.Zero)
        {
            StatusText.Text = "Failed to start — the node could not bind its sockets or open its data directory.";
            SendButton.IsEnabled = false;
            MessageBox.IsEnabled = false;
            return;
        }

        _deviceId = GabrielNative.DeviceId(_node);
        DeviceIdText.Text = $"this device: {_deviceId}";
        _messages.Add(MessageEntry.Notice(
            $"Node started as \"{Environment.MachineName}\". Data in {dataDir}."));
    }

    private void Refresh()
    {
        if (_node == IntPtr.Zero)
        {
            return;
        }

        // Peers: replace in place rather than clearing, so the recipient
        // ComboBox doesn't lose the user's selection every 750ms.
        var latest = GabrielNative.Peers(_node);
        var selectedId = (RecipientBox.SelectedItem as PeerView)?.DeviceId;

        foreach (var peer in latest)
        {
            var existing = _peers.FirstOrDefault(p => p.DeviceId == peer.DeviceId);
            if (existing is null)
            {
                _peers.Add(peer);
            }
            else if (Math.Abs(existing.LastSeenSecs - peer.LastSeenSecs) > 0.01f
                     || existing.Routable != peer.Routable)
            {
                _peers[_peers.IndexOf(existing)] = peer;
            }
        }

        foreach (var gone in _peers.Where(p => latest.All(l => l.DeviceId != p.DeviceId)).ToList())
        {
            _peers.Remove(gone);
        }

        if (selectedId is not null && RecipientBox.SelectedItem is null)
        {
            var restored = _peers.FirstOrDefault(p => p.DeviceId == selectedId);
            if (restored is not null)
            {
                RecipientBox.SelectedItem = restored;
            }
        }

        foreach (var msg in GabrielNative.TakeInbox(_node))
        {
            _messages.Add(MessageEntry.Received(msg));
            ScrollMessagesToEnd();
        }

        var routable = _peers.Count(p => p.Routable);
        StatusText.Text = _peers.Count switch
        {
            0 => "No other devices found yet — open Gabriel on another machine on this network.",
            1 => $"1 device nearby · {routable} reachable for messaging",
            _ => $"{_peers.Count} devices nearby · {routable} reachable for messaging",
        };
    }

    private void SendButton_Click(object sender, RoutedEventArgs e) => SendMessage();

    private void MessageBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter)
        {
            SendMessage();
            e.Handled = true;
        }
    }

    private void SendMessage()
    {
        if (_node == IntPtr.Zero)
        {
            return;
        }

        var text = MessageBox.Text.Trim();
        if (text.Length == 0)
        {
            return;
        }

        if (RecipientBox.SelectedItem is not PeerView recipient)
        {
            _messages.Add(MessageEntry.Notice("Pick a device to send to first."));
            ScrollMessagesToEnd();
            return;
        }

        var reached = GabrielNative.SendMessage(_node, recipient.DeviceId, text);
        if (reached < 0)
        {
            _messages.Add(MessageEntry.Notice("Send failed — the core rejected the message."));
        }
        else
        {
            _messages.Add(MessageEntry.Sent(recipient.ShortId, text, reached));
        }

        MessageBox.Text = "";
        ScrollMessagesToEnd();
    }

    private void ScrollMessagesToEnd()
    {
        if (_messages.Count > 0)
        {
            MessageList.ScrollIntoView(_messages[^1]);
        }
    }

    private void Shutdown()
    {
        _timer?.Stop();
        if (_node != IntPtr.Zero)
        {
            GabrielNative.Stop(_node);
            _node = IntPtr.Zero;
        }
    }
}
