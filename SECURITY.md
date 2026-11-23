# Security

This document says what these tools protect, what they do not, and why. It is version 0.1 software and
has not been audited.

## The short version

**What you get**

- **No secret at rest.** The API token exists on disk only as a file that the card's key in slot 9D can
  open. A program that reads your files, a backup, or a stolen laptop without the card yields ciphertext.
- **Keys that cannot be copied.** The private keys in slots 9D and 9A were generated on the card and
  cannot be exported. Whatever runs on your machine, the SSH key cannot be taken away and used elsewhere.
- **Use only while you allow it.** Between "locked" and "unlocked" stand the card, its PIN, and you at a
  terminal. Each unlock has a time limit and can be ended at once.

**What you do not get**

- **A sandbox.** While something is unlocked, every program running as you can use it. That includes the
  AI agent.
- **Protection from a program that already runs as you when you unlock.** Such a program can learn the PIN
  or the secret at that moment. It can stand in for the pivcard agent, put its own `age` or its own copy
  of these tools first on your `PATH`, change your shell's startup files, show you a false PIN prompt, or
  read your keystrokes. With the PIN, and the card in the reader, it can use both slots.

So these tools remove the standing risk of secrets in files, and they bound what a session can do to "use
while unlocked". If the AI agent may be hostile rather than merely careless, run it where it cannot write
to your home directory or reach the pivcard agent's control endpoint: another user account, a container
or a virtual machine. Such a setup is outside this repository and has not been tested with it.

## What a program running as you can do

| State | It can | It cannot |
|---|---|---|
| Nothing unlocked | Read ciphertext and public keys. Send wrong PINs to the card until the card blocks itself. Prepare to capture the PIN or a secret at your next unlock (see above) | Decrypt an entry. Get a signature |
| An entry is unlocked | Read that entry, by asking the pivcard agent or by reading the environment of a command started with it. Keep a copy, and keep the entry in the agent beyond your time limit | Read other entries. Use the card |
| SSH is unlocked | Have the card sign anything: logins wherever the card's key is accepted, and also files or Git commits | Copy the key. Use it after you lock or the time limit ends |
| It knows the PIN and the card is in the reader | Everything the card can do | Copy the keys |

Consequences worth spelling out:

- **Unlocking is a decision to trust what runs in your session for that time.**
- **A token that was read while unlocked stays valid** until you revoke it at the provider. The time limit
  and `withsecrets lock` end the exposure of a secret that has not been read yet. They cannot take back
  one that has. Prefer narrowly scoped tokens in a project of their own.
- **The SSH key signs whatever it is given.** The pivcard agent does not look at what it signs. Do not
  register the card's SSH key for other purposes, such as signing Git commits or logging in to other
  services, unless an unlocked session may act there too.
- **There is no confirmation per use.** The card has no button. Between unlock and lock, signatures are
  given to any program of yours that asks.
- **Your PIN is only as safe as the place you type it.** Type it only at a prompt in a terminal you opened
  yourself, for a command you typed yourself. A PIN prompt that appears in the AI agent's own terminal, or
  that you did not ask for, is not one to answer. Never type or paste the PIN into a chat with the agent.
  Take the card out of the reader when you are not using it.
- **Any program can block the card** by sending wrong PINs. These tools never do (see below), but they
  cannot stop another program. Unblocking needs the card's PUK.
- **Root** can read the memory of any process, and so defeats all of this.
- **A card with publicly known administration keys protects nothing.** Test and evaluation cards may
  still accept the published GlobalPlatform test keys. With those, any program can set a new PIN over the
  card's administration channel without knowing the old one, and then use the card. Everything in this
  document assumes administration keys that only you hold.

## How the tools limit the damage

- **A wrong card gets no PIN.** Before any PIN is sent, the slot's certificate is read (no PIN needed) and
  its public key is compared with the one recorded for your card. Another card left in the reader by
  mistake gets no PIN and loses no PIN try. Before `withsecrets init` and the first `pivcard ssh unlock`
  there is nothing to compare with. This is a guard against mix-ups. It does not authenticate the card: a counterfeit
  card made to show your public key would pass the check and receive the PIN.
- **Never left unlocked.** A PIV card has a single PIN state: once verified, every program can use the
  keys in slots 9A and 9D until the card is logged out or reset. Each use here is one PC/SC transaction:
  check the key, send the PIN, do one operation, log out. If the card refuses the logout command, it is
  reset as the transaction ends. A stop signal (Ctrl-C, a closing terminal) that arrives in the middle
  waits until the logout is done.
- **PIN tries are protected.** The tools never use the last PIN try. A PIN that is not 6 to 8 digits is
  rejected before it reaches the card. If the card ever answers "wrong PIN" to the pivcard agent, the
  agent forgets the PIN at once, and requests that were waiting for the card do not send it again.
- **Only three commands ask for a PIN**, and only when their standard input is a terminal:
  `withsecrets unlock`, `pivcard ssh unlock` and `pivcard check`. Running a command with
  `withsecrets <entry> -- ...` never asks; a locked entry gives exit status 3. With no terminal, nothing at
  all is sent to the card.
- **Prompts can be switched off for a whole environment.** With `PIVCARD_NO_PROMPT=1` set, the three
  commands refuse, and so does the plugin when `age` is used directly. Set it in the environment you give
  the AI agent, so that it cannot bring up a PIN prompt in its own terminal by accident. A hostile program
  can unset a variable; this is a guard against mistakes, not a barrier.
- **The PIN is never in a file, a command line or the environment.** It is typed at a prompt and passed
  in memory. `withsecrets` removes `AGEDEBUG` from age's environment, because age's plugin debugging
  prints the conversation with the plugin, PIN included. If you call `age` directly, do not set
  `AGEDEBUG=plugin`.
- **Secret values are never on a command line.** They are passed to the command in its environment, and
  to the pivcard agent over its socket.
- **Two endpoints.** `ssh` is only ever given the agent's SSH endpoint, which lists one key and signs.
  The unlocked entries and the lock controls are on a separate endpoint, so a remote host reached with
  agent forwarding cannot get at them.
- **Other users are kept out.** On Linux the sockets are in a directory only you can enter, and the agent
  checks the user of every connecting process. On Windows, before a command sends a PIN or a secret, it
  confirms that the pipe is served by a program running as you. These checks tell your account from other
  accounts. They do not tell the real pivcard agent from another program running as you.
- **Less to read from memory, on Linux.** The pivcard agent, the plugin, `withsecrets` and `pivcard` mark
  themselves non-dumpable, so other processes of yours cannot read their memory through `ptrace` or
  `/proc`. `age` itself, which passes the PIN from its prompt to the plugin, does not.
- **The pivcard agent does not import from the current directory.** It is started so that neither that
  directory nor `PYTHONPATH` is on its import path. On Windows, `age`, `ssh` and the command given to
  `withsecrets` are not taken from the current directory either. The commands you type yourself are
  ordinary Python programs: with an empty or relative entry in `PYTHONPATH` (for example `PYTHONPATH=.`)
  they import from the directory you are in. Unlock from a terminal without such a `PYTHONPATH`.
- **Time limits are wall-clock time.** On Linux they also count the time the computer is suspended.
- **An entry may not set the best-known variables that change what a program loads** (`PATH`, `LD_*`,
  `PYTHON*`, `GIT_*` and some more). A command is not run with such an entry. The list cannot be
  complete: treat an entry that someone else could have written like a script written by them.
- **The Hetzner example** sends the token only to the Hetzner API and refuses HTTP redirects. It uploads
  only the public SSH key. It deletes only what it labelled.

## Known gaps

- **On Windows, two things are weaker than on Linux.** The memory of the programs is not protected from
  other programs of the same user. And the agent does not check who connects to its pipes; it relies on
  the default permissions of a named pipe. Those give you, administrators and the system full access, and
  everyone else read access only, so another user cannot send it a request (checked on Windows 11). The
  pipes are created to refuse clients on other machines; that was not tested from a second machine.
- **On Windows, plain `age -d` can wait for ever.** age asks for the PIN on the console. A program started
  with a hidden console gets a prompt nobody can see or answer. `withsecrets` does not have this problem:
  it asks only when its own input is a terminal.
- **`age` and the plugin are found on your `PATH`.** These tools start whichever `age` comes first, and
  age starts whichever `age-plugin-pivcard` comes first. A program that can change your `PATH` or your
  shell's startup files can put its own in front, and would then see the PIN.
- **Entries are encrypted, not signed.** Encrypting needs only the card's public key, so a program that
  can write your files can replace an entry, for example with a token for an account of its own. The
  tools do not detect that.
- **The agent's memory may be swapped to disk.** Use encrypted swap.
- **The command you run inherits the secret.** So do its child processes, and on Linux other processes
  of yours can read a process's environment.
- **The identity file and the saved SSH public key say which card is yours.** They hold no secret, but a
  program that can rewrite them can make you encrypt new entries to a key it controls.
- **Every recipient in `recipients.txt` can open every entry without the card.** A backup key is a
  card-free copy of all your secrets. Keep it offline and apart from the encrypted files.
- **Contactless use has not been tried.** Only the contact interface was tested.
- **In the Hetzner example, the server's SSH host key travels as cloud-init user data.** Hetzner stores
  it, any program in the server can read it, and so can anyone who holds the API token. Strict host-key
  checking is therefore as strong as that key is secret. It identifies one throwaway server and nothing
  else.

## Cryptography

Nothing here is new. Files use age's standard `p256tag` recipient type: HPKE (RFC 9180) in base mode with
DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305. The primitives come from the Python
`cryptography` package. The HPKE composition is in this repository; it is checked against the RFC 9180
test vectors and against files written and read by age itself. The card performs the P-256 key agreement
(for decryption) and ECDSA signature (for SSH) with keys that never leave it.

## What was checked on a real card

On three Cryptnox PIV cards in a contact reader, with age 1.3.2 and OpenSSH 9.6 on Ubuntu 24.04. One card
was already personalised; the other two were blank and were set up with the commands in
[docs/card-setup.md](docs/card-setup.md). All three gave the same results:

- age files encrypted to the card's recipient decrypt with the card and the PIN;
- with no terminal, nothing is sent and the PIN-try counter does not move;
- the card reports "PIN not verified" after every decryption, after the PIN check of `pivcard ssh unlock`
  and after each SSH signature;
- while an entry or SSH is unlocked, another process is refused a key agreement on slot 9D without a PIN;
- signatures made through the agent verify with OpenSSH against the card's public key;
- after `pivcard ssh lock`, OpenSSH sees no key and gets no signature;
- a real login to an OpenSSH 9.6 server with the options the Hetzner example uses is accepted with the
  card's key, and the card is locked again afterwards; the agent is not forwarded to the server;
- a server that presents another host key than the pinned one gets no login ("Host key verification
  failed");
- before `pivcard ssh unlock` and after `pivcard ssh lock`, the same login is refused.

With the Hetzner example against the real Hetzner Cloud API (one server, Ubuntu 24.04):

- Hetzner accepts the card's ECDSA P-256 public key;
- the first login, seconds after the server came up, passed strict host-key checking against the key
  generated locally, and the server's host key file holds that key;
- on the server, the card's key is the only authorised key and password logins are off;
- with the token or SSH locked, the script exits with status 3 and sends nothing;
- after `destroy`, the Hetzner project held no server, SSH key or IP address.

The check "another card gets no PIN" is covered by tests with a software card.

The code changed once more after a security review: the logout now also runs when a stop signal arrives
during the PIN check, a card that cannot log out is reset inside the transaction, and only the last PIN
try is held back. The third card, and the Windows run below, were tested with that final code. The first
two cards were tested before it.

The run against the Hetzner API was also made before the last changes to the example script (it no
longer has an `unlock` command, it marks the end of the options of `ssh`, and it checks labels and
addresses itself). Those changes are covered by the tests against a stand-in for the API and by the
login tests above, not by a second run against the real API.

**These tests show that the tools behave as described. They do not show that the test cards kept a
secret.** Both test cards accept the publicly known test administration keys, which is the case described
above as protecting nothing.

## What was checked on Windows

On Windows 11 with Python 3.12, age 1.3.2 and OpenSSH for Windows 9.5, with a Cryptnox PIV card in a
contact reader (the card that was set up from blank on Linux). The results match the Linux ones:

- `pivcard check` passes: one decryption, one signature, the card locked again after each;
- with no terminal, nothing is sent and the PIN-try counter does not move;
- the card reports "PIN not verified" after `withsecrets unlock`, after the PIN check of
  `pivcard ssh unlock`, after each SSH signature and after an SSH login;
- while an entry or SSH is unlocked, another process is refused a key agreement on slot 9D without a PIN;
- `ssh-add`, `ssh-keygen` and `ssh` from OpenSSH for Windows use the agent's named pipe; a login to an
  OpenSSH server with the options of the Hetzner example is accepted with the card's key, and with
  another pinned host key it is refused;
- after `pivcard ssh lock`, OpenSSH sees no key, gets no signature and cannot log in;
- with several readers attached and none chosen, the commands refuse to pick one and send nothing.

The whole test suite also passes there with a software card, including the PIN typed at age's prompt on a
Windows console. Not run on Windows: the Hetzner example against the real API (it ran from Linux).

## Reporting a problem

Please use "Report a vulnerability" under the Security tab of the GitHub repository, so the report stays
private until there is a fix.
