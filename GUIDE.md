# Gabriel, in plain English

This guide is for people who want to *use* Gabriel. There is no code in it.

If you want the technical detail, read [README.md](README.md) instead.

---

## What is Gabriel?

**Gabriel lets your devices talk to each other, and share one internet
connection, without needing the internet to introduce them.**

Normally, when you message someone in the same room, your message travels
to a company's server somewhere far away and comes back. If the network is
down, nothing works — even though the person is standing right there.

Gabriel skips that trip. Your devices find each other directly over the
Wi-Fi or network you are already on, and talk to each other.

---

## What it does today

### 1. Your devices find each other automatically

Open Gabriel on two computers on the same network. Within a few seconds,
each one sees the other by name. You did not sign up for anything, create
an account, or type in an address.

Each device has its own permanent identity, and every announcement it
makes is signed. That means **nobody can pretend to be your device**. If
someone on your network tries to impersonate you, the other devices
reject it automatically.

### 2. You can send messages without the internet

Pick a device, type a message, send it. It goes directly across your
local network.

If the other device is switched off, the message waits. It is saved on
your disk, so it survives closing Gabriel or restarting your computer. The
moment that device comes back, the message goes out.

> ⚠️ **Important, and we would rather tell you than hide it:** messages
> are **signed but not encrypted**. That means the recipient can prove it
> really came from you and that nobody changed it. But any device that
> passes the message along can read it. **Do not send anything private
> yet.** Proper end-to-end encryption is the next thing being built.

### 3. You can share your internet with people near you

This is the big one.

If you have internet and the person next to you does not, you can share
it — safely, and without giving them your Wi-Fi password.

They connect to your Gabriel, prove which device they are, and their
traffic goes out through your connection. You stay in control.

### 4. You can see and limit exactly how much they use

This is what makes sharing practical rather than scary.

Open the **Data usage** tab. You will see:

- every device that has used your connection
- exactly how many megabytes each one used
- how much they have left, if you gave them a limit

You can give someone an allowance — say 500 MB. When they hit it, their
connection stops. Not "eventually", not "at the next login" — **the
moment they reach the limit, mid-download.**

And the count does not reset. If they disconnect and come back, Gabriel
remembers what they already used. Closing the app does not wipe it either.

### 5. It has a crypto wallet built in

Gabriel can hold addresses on 13 blockchains from a single recovery
phrase — Bitcoin, Ethereum, Solana and ten others.

**Your keys stay on your machine.** Gabriel never holds your money, never
has access to it, and cannot freeze or lose it. Every payment goes
directly from you to the other person on the public blockchain.

The clever part: because each Gabriel device already has a verified
identity, your device can publish "you can pay me at this address" over
the network, signed. Anyone can check it is genuinely yours. No middleman,
no address book service, no risk of someone swapping in their own address.

Right now the wallet can **receive on all 13 chains** and **send on 7 of
them** (Ethereum, Arbitrum, Optimism, Base, Polygon, BNB Chain,
Avalanche). The other six can receive but not yet send — sending is being
added one at a time, carefully, because a mistake there loses money
permanently.

---

## How this helps you

### If you are sharing a home, flat or office

One person has the good connection. Everyone else is buying data bundles.

With Gabriel, that one person shares it — and actually knows who used
what, instead of guessing. No arguments about who burned through the data.
No handing your Wi-Fi password to five people.

### If your network goes down

Cable cuts, outages, and shutdowns happen. When they do, everything
stops — including the ability to tell people what is going on.

Gabriel keeps working on your local network. Your building, your office,
your market can still communicate. When the connection comes back,
anything waiting goes out automatically.

### If you are somewhere with bad coverage

Building sites. Farms. Markets. Events. Boats. Anywhere the signal is
weak but people still need to reach each other.

Gabriel does not need a phone mast. If devices can see the same network,
they can talk.

---

## How this helps if you want to run it as a business

### Selling spare bandwidth

You have a connection with room to spare. Your neighbours are paying a lot
for small data bundles. Gabriel gives you the three things you need to
turn that into income:

| You need | Gabriel gives you |
| --- | --- |
| People to find you | Automatic discovery — they see you without setup |
| To know who is who | Every device has a verified identity |
| To count what they used | Per-device metering, down to the byte |
| To enforce a limit | Allowances that cut off mid-session |
| To get paid | A built-in wallet, paid directly to you |

**A worked example, using your own numbers.** At $0.10 per gigabyte:

- Someone buying 500 MB pays you $0.05
- Someone using 10 GB a month pays you $1.00
- Sharing 100 GB a month earns you about $10

Whether that is worth it depends on what your own data costs you. If you
are on unlimited fibre, nearly all of it is profit. If you are reselling
mobile data at close to what you paid, it is not worth the effort. **Check
your own numbers before you build a business on it.**

### What a payment actually costs you

Sending money on a blockchain costs a small fee. That fee matters a lot
when the payments are tiny.

We measured this live, and it varies enormously:

| Network | Cost per payment | Smallest sensible payment |
| --- | --- | --- |
| Optimism | about $0.0002 | around 180 MB |
| Avalanche | about $0.0002 | around 250 MB |
| Base | about $0.001 | around 1 GB |
| Ethereum main network | about $0.01 | around 8 GB |

**The practical advice:** do not take payment after every small session.
Let it add up, and settle once per gigabyte or so. And check the rates
before you choose — they change daily. Gabriel has a built-in command that
measures them for you.

### Two things to check before you start

1. **Your own data cost.** If you are buying data at $0.09/GB and selling
   at $0.10/GB, there is no business there. The gap is the business.
2. **Your internet contract.** Many home internet contracts forbid
   reselling your connection, even where no licence is needed. That is a
   contract issue, not a legal one, but an internet provider cutting you
   off would end things quickly. Worth reading yours.

---

## Getting started

### Install

1. Get `gabriel-desktop.exe`
2. Run it. That is the whole installation.

It creates its own settings folder the first time it runs and generates
your device identity automatically.

### Your first five minutes

1. **Open it.** The Overview tab shows your device's name and ID.
2. **Rename your device** to something you will recognise, like
   "roland-laptop".
3. **Open Gabriel on a second computer** on the same network. Within a few
   seconds each should appear in the other's Network tab.
4. **Send a message.** Messages tab, pick the device, type, send.
5. **Try sharing.** Gateway tab → *Start sharing*. The other device can
   now route through your connection.
6. **Watch it count.** Data usage tab. You will see exactly what they used.

### Giving someone an allowance

1. Open **Data usage**
2. Find their device, click **Set allowance**
3. Type a number of megabytes

That is it. When they reach it, they stop.

### Running two copies on one computer

Useful for testing without a second machine:

```
GABRIEL_DATA_DIR=C:\gabriel-b GABRIEL_NAME=test-node gabriel-desktop.exe
```

---

## Questions people ask

**Does it need the internet?**
Not for finding devices or messaging — those work on a local network
alone. You only need internet for the sharing feature (obviously — that is
the thing being shared) and for blockchain payments.

**Does it use my mobile data?**
No. Gabriel talks over your local network. It only uses internet data if
you are routing through someone's gateway, or they are routing through
yours.

**Can someone use my connection without me knowing?**
No. They have to connect to your gateway deliberately, and every byte is
recorded against their device.

**Can I stop someone?**
Yes. Set their allowance to zero, or stop sharing entirely. Either takes
effect immediately.

**Is my money safe in the wallet?**
Your keys never leave your computer, and Gabriel never holds your funds.
But that cuts both ways: **if you lose your recovery phrase, nobody can
recover it for you.** There is no password reset. Write it down and keep
it somewhere safe and offline.

**Are my messages private?**
**Not yet.** They are signed, so nobody can forge or alter them, but they
are not encrypted, so a device relaying them could read them. Treat them
like a postcard. Encryption is next on the list.

**Does it work on my phone?**
Not yet. Windows only for now. Phone support is planned and is the biggest
remaining piece of work.

---

## What is not built yet

We would rather you know this up front than find out the hard way.

| Not yet built | What it means for you |
| --- | --- |
| **Message encryption** | Messages can be read by devices relaying them |
| **Deciding who may connect** | Anyone on your network can ask to use your gateway — you can limit how much they use, but not yet who may ask |
| **Phone app** | Windows computers only |
| **Sending on 6 of 13 chains** | Bitcoin, Litecoin, Dogecoin, Solana, Tron and Cosmos can receive but not send |
| **Automatic payment for data** | Metering counts usage; billing someone for it is still manual |

The app itself will tell you these things too. Every screen that has a gap
says so, right next to the buttons it affects, rather than burying it in a
document you might not read.
