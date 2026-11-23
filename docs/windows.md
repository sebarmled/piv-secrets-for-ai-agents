# Windows

The same commands work on Windows. The Hetzner example is written to run there too; its SSH options were
tested on Windows, the example as a whole only from Linux.

Install as shown in the README. pip fetches a ready-made smart card library, and the Smart Card service
is part of the system. You also need [age](https://github.com/FiloSottile/age/releases) 1.3 or later and
the OpenSSH client on `PATH`.

Five things differ from Linux:

- **Named pipes, not socket files.** The pivcard agent (the background program of this project, not the
  AI agent) listens on two named pipes.
  `pivcard ssh status` and `pivcard ssh socket` print the name to give to OpenSSH, written with forward
  slashes (`//./pipe/pivcard-ssh-<you>`), because OpenSSH reads a backslash in an option as an escape
  character.
- **A check on who serves the pipe.** A pipe name can be taken by any program that asks first. So before
  a command sends a PIN or a secret, it confirms that the pipe is served by a program running as you. If
  a program of another user has taken the pivcard agent's pipe name, the command stops and says so. The
  check cannot tell the pivcard agent from another program running as you.
- **Local clients only.** The pipes are created so that they refuse connections from other machines.
  (Named pipes are reachable over the network by default.) This was not tested from a second machine.
- **`ssh.exe` needs a console window.** Started from a session without one, it runs the remote command
  but then never exits. That is how OpenSSH for Windows behaves, with or without these tools.
- **One kind of prompt.** Use the commands either always from a normal prompt or always from an
  administrator prompt. A pivcard agent started from an administrator prompt cannot be reached from a
  normal one.

Files are under `%APPDATA%\pivcard\` and `%APPDATA%\withsecrets\`, or under `XDG_CONFIG_HOME` when that
variable is set. Where the README writes `~/piv-secrets-for-ai-agents/...`, give the full path of your clone.

What is weaker on Windows than on Linux is listed under "Known gaps" in [SECURITY.md](../SECURITY.md).

## What was tested

Windows 11, Python 3.12, age 1.3.2, OpenSSH for Windows 9.5, a Cryptnox PIV card in an Identiv uTrust
2700 R contact reader: the card self-test, `withsecrets` (locked, unlocked on a console, used from a shell
without a console), the agent on named pipes, signatures through `ssh-keygen`, and an SSH login with the
options of the Hetzner example. The test suite passes there too. The Hetzner example itself was run
against the real API from Linux only.
