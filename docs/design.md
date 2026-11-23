# Design

## File format

Files are ordinary age files with age's standard `p256tag` recipient stanza: HPKE (RFC 9180) with
DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305. The format and the algorithms are age's own;
nothing new was designed. The HPKE steps are written out in this repository on top of the Python
`cryptography` package, and are checked against the RFC 9180 test vectors and against age itself.

- A recipient prints as `age1tag1...`, which age 1.3 and later encrypt to without any plugin, and as
  `age1pivcard1...` for the plugin.
- The identity `AGE-PLUGIN-PIVCARD-1...` holds the slot number and the public key. It holds no secret.
- The card contributes one thing: the raw ECDH result between its private key in slot 9D and the file's
  ephemeral key.

## Talking to the card

Standard SP 800-73 commands over PC/SC, the usual interface to smart card readers. Only short commands
are used, so that plain USB readers work. Every use of a private key is one unit inside one PC/SC
transaction, during which no other program can talk to the card:

1. read the slot's certificate (no PIN) and check that it holds the expected public key;
2. only then send the PIN;
3. do the one operation (a key agreement on slot 9D, or a signature on slot 9A);
4. log the card out.

A card other than yours, left in the reader by mistake, therefore does not receive the PIN, and the card
is never left unlocked. (The check compares public keys. It guards against mix-ups; it cannot detect a
counterfeit card made to show your public key.)

The tools never use the last PIN try, so a script cannot block the card through them. The price: once
wrong PINs have brought the counter down to one, the tools refuse the right PIN as well. Verify the PIN
once with the card's own tool, which puts the counter back. `pivcard status` shows the counter.

## Why the logout matters

A PIV card has one PIN state for the whole card. Once any program has sent the PIN, every other program
can use the keys in slots 9A and 9D with no PIN, until the card is reset or logged out. We confirmed this
on the test card: after one process verified the PIN and exited, a second process used slot 9D with no
PIN.

A tool that unlocks the card and leaves it that way has opened both slots for every program of the user.
That is why each operation ends with a logout, and why the two slots can be unlocked separately here: the
API token and the SSH key have separate time limits and separate lock commands, although the card has a
single PIN.

## The pivcard agent

A small background process, started on demand, that holds in memory what you have unlocked: decrypted
entries (named sets of secrets), and the PIN while SSH is unlocked. It exits 30 seconds after it holds
nothing. It is not the AI agent; this page calls it the pivcard agent throughout.

It is started without the current directory on its import path, so that a file dropped into a project
directory cannot run inside the process that holds the PIN. Its time limits count the time the computer
spends suspended (on Linux).

It has two endpoints (Unix sockets on Linux, named pipes on Windows):

- **The SSH endpoint** is the only one ever given to `ssh`. It answers "list keys" and "sign" and nothing
  else.
- **The control endpoint** holds the entries and the lock controls. Because it is separate, a remote host
  reached with agent forwarding cannot get at them.

On Linux the sockets are in a directory only you can enter, the pivcard agent checks the user of every
connecting process, and it marks itself non-dumpable, like `ssh-agent`. These measures keep other users
out. They do not tell the pivcard agent from another program running as you; see
[SECURITY.md](../SECURITY.md).

## Why not OpenSC and PKCS#11 for SSH?

That was the first design, and on Ubuntu 24.04 (OpenSC 0.25.0~rc1) it left the card unlocked. With
`ssh-agent` and the OpenSC PKCS#11 module, the card stayed in the "PIN verified" state after `ssh-add -s`,
after every signature, and after removing the key with `ssh-add -e`. While it does, any program of yours
can use the other slots, including the 9D key that protects the secrets, without a PIN.

OpenSC's PKCS#11 module has a setting meant for this, `atomic = true` in `opensc.conf`. With this build
it did not help: the debug log reads `pkcs15_logout: Clearing PIN state without calling sc_logout()`, so
the card's logout command is never sent, and the module then kept the card for its exclusive use, which
blocked every other program.

Hence the built-in pivcard agent, which logs the card out after every single operation and uses the same
card sequence on Linux and Windows.

## Questions

**Why not `age-plugin-yubikey`?** It relies on commands specific to YubiKeys and does not work with
other PIV cards. If you have a YubiKey, use `age-plugin-yubikey`. A YubiKey can also require a touch,
which a plain card cannot.

**Why does the pivcard agent keep the PIN while SSH is unlocked?** The card needs the PIN for each signature and
is logged out after each one. Without a button on the card, the alternative is typing the PIN for every
login. Choose a short `--hours` value, and lock when you are done.

**Why is the API token not stored on the card itself?** PIV is built around keys and certificates. Its
PIN-protected data objects are few and small, and writing one needs the card's administration key. What
every PIV card does well is decrypt. So the token is a file that only the card can open, and the same
card can protect any number of such files.

**Can I use RSA keys?** No. The age format used here is defined for P-256, and the agent signs with
`ecdsa-sha2-nistp256`.

**Can the AI agent's shell bring up a PIN prompt?** Only three commands ask for a PIN:
`withsecrets unlock`, `pivcard ssh unlock` and `pivcard check`, and only when their standard input is a
terminal. Running a command with `withsecrets <entry> -- ...` never asks. Used directly, `age` asks on the
controlling terminal if there is one. Setting `PIVCARD_NO_PROMPT=1` in the AI agent's environment switches
all of these off. In every case the AI agent would still need the PIN, which is the thing it does not
have. So never answer a PIN prompt you did not start.

**Can a program that knows the PIN use the card?** Yes. Anyone with the card in the reader and the PIN
can use it. Type the PIN only in your own terminal, never in a chat with the AI agent.
