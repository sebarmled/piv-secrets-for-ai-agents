"""withsecrets: run a command with secrets in its environment only. The secrets are age files sealed
to a PIV card; these tools never write them to a file in clear.

    withsecrets init                                   write the identity file from the card (no PIN)
    withsecrets set <entry> <NAME>...                  type each value at a hidden prompt (no card needed)
    withsecrets set <entry>                            or: encrypt KEY=VALUE lines from standard input
    withsecrets unlock <entry>... [--ttl SECONDS]      decrypt once (PIN on YOUR terminal), hold in memory
    withsecrets status                                 which entries are unlocked, minutes left
    withsecrets lock [<entry>]                         forget one entry, or all
    withsecrets list <entry>                           variable NAMES of an unlocked entry (no values)
    withsecrets <entry>... -- <command> [args...]      run the command with the entries' variables

An entry is a file of KEY=VALUE lines (blank lines and # comments ignored). `set` replaces the whole
entry. If a file `recipients.txt` exists next to the identity file, entries are also encrypted to the
age recipients listed in it (a second card, or an offline backup key).

Only `unlock` asks for the card PIN, and only on a terminal. Running a command never asks: if an entry
is locked, nothing is sent to the card and the exit status is 3. (`--cached-only` before the entries is
accepted and means the same.) With PIVCARD_NO_PROMPT=1 in the environment, `unlock` refuses too.

Exit status: 2 usage, 3 locked, 4 decryption failed, 1 another failure, 127 command not found,
otherwise the command's own.
"""
from __future__ import annotations

import base64
import contextlib
import getpass
import os
import re
import subprocess
import sys
from pathlib import Path

from . import agent, paths, piv, tagfmt
from .plugin import CardError

EXIT_USAGE, EXIT_LOCKED, EXIT_DECRYPT = 2, 3, 4
ENTRY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*\Z")
PAIR = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
# Variables that change which code a program loads or runs. An entry is encrypted, not signed: anyone who
# can write the store can replace it. So an entry is never allowed to set one of these. The list holds the
# well-known ones and cannot be complete. Names are compared without regard to case, as Windows does.
LOADER_VARIABLE = re.compile(
    r"(?:LD_|DYLD_|PYTHON|GIT_|PIVCARD_|WITHSECRETS_|HZ_|SSH_|XDG_)[A-Z0-9_]*\Z"
    r"|(?:PATH|PATHEXT|HOME|SHELL|ENV|BASH_ENV|IFS|PS4|SHELLOPTS|BASHOPTS|PROMPT_COMMAND|ZDOTDIR|EDITOR|VISUAL"
    r"|PAGER|GCONV_PATH|NODE_OPTIONS|NODE_PATH|PERL5OPT|PERL5LIB|PERLLIB|RUBYOPT|RUBYLIB|CLASSPATH"
    r"|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|COMSPEC|SYSTEMROOT)\Z")
DEFAULT_TTL = 2 * 3600


class Fail(Exception):
    def __init__(self, message: str, status: int = 1):
        super().__init__(message)
        self.status = status


def home() -> Path:
    return Path(os.environ.get("WITHSECRETS_HOME") or paths.config_dir("withsecrets"))


def identity_file() -> Path:
    return home() / "identity.txt"


def recipients_file() -> Path:
    return home() / "recipients.txt"


WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def entry_file(name: str) -> Path:
    if not ENTRY.match(name):
        raise Fail(f"invalid entry name {name!r} (letters, digits, . _ - and / between parts)", EXIT_USAGE)
    for part in name.split("/"):                       # names Windows would not store as ordinary files
        if part.endswith(".") or part.split(".")[0].upper() in WINDOWS_DEVICES:
            raise Fail(f"invalid entry name {name!r} ({part!r} is not a usable file name on Windows)", EXIT_USAGE)
    return home() / "store" / (name + ".age")


def parse_pairs(text: str) -> tuple[list[tuple[str, str]], int]:
    """KEY=VALUE lines -> ([(key, value)], number of lines ignored). Values are taken literally."""
    pairs, ignored = [], 0
    for line in text.split("\n"):                     # only a newline ends a line (not form feed, U+2028, ...)
        line = line.removesuffix("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        line = line.removeprefix("export ")
        key, _, value = line.partition("=")
        if PAIR.match(line) and value:                 # "NAME=" with nothing after it is not a secret
            pairs.append((key, value))
        else:
            ignored += 1
    return pairs, ignored


def _age_env() -> dict[str, str]:
    """Environment for age: no protocol debugging (it prints the PIN), and our plugin reachable as a
    fallback at the END of PATH, for installs where the scripts directory is not on PATH."""
    env = {k: v for k, v in os.environ.items() if k != "AGEDEBUG"}
    extra = [str(Path(sys.argv[0]).resolve().parent), str(Path(sys.executable).parent)]
    env["PATH"] = os.pathsep.join([env.get("PATH", ""), *extra])
    return env


def _age() -> str:
    exe = paths.find_program("age")
    if not exe:
        raise Fail("the `age` program is not installed or not on PATH (https://age-encryption.org)")
    return exe


def _need_identity() -> Path:
    path = identity_file()
    if not path.is_file():
        raise Fail(f"no identity file at {path}. Insert the card and run: withsecrets init")
    return path


# ------------------------------------------------------------------ the in-memory copy (the agent)
def cached(name: str) -> tuple[str, int] | None:
    try:
        reply = agent.control({"op": "get", "name": name})
    except agent.AgentUnavailable:
        return None
    if not reply.get("ok"):
        return None
    return base64.b64decode(reply["data"]).decode("utf-8", "replace"), int(reply["seconds_left"])


def hold(name: str, text: str, ttl: int) -> None:
    reply = agent.control({"op": "put", "name": name, "data": base64.b64encode(text.encode()).decode(), "ttl": ttl},
                          autostart=True)
    if not reply.get("ok"):
        raise Fail(f"the agent refused to hold {name}: {reply.get('error')}")


def decrypt(name: str) -> str:
    """Decrypt an entry with age + the card. Only ever called with a terminal attached."""
    path = entry_file(name)
    if not path.is_file():
        raise Fail(f"no such entry: {name} ({path})", EXIT_USAGE)
    print(f"withsecrets: unlocking {name} (card PIN)", file=sys.stderr, flush=True)
    proc = subprocess.run([_age(), "-d", "-i", str(_need_identity()), str(path)],
                          stdout=subprocess.PIPE, env=_age_env(), check=False)
    if proc.returncode != 0:
        raise Fail(f"could not decrypt {name}", EXIT_DECRYPT)
    return proc.stdout.decode("utf-8", "replace")


def unlocked(name: str) -> str:
    """The plaintext of an entry that is unlocked. Never touches the card and never asks for anything."""
    entry_file(name)                                    # validates the name
    hit = cached(name)
    if hit is None:
        raise Fail(f"{name} is locked. In your own terminal run: withsecrets unlock {name}", EXIT_LOCKED)
    return hit[0]


def on_terminal() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def can_prompt() -> bool:
    """May the card PIN be asked for here? age asks on the controlling terminal, which can exist even when
    our stdin is not one. We only let it when the person running us is demonstrably at a terminal, and
    never when PIN prompts are switched off for this environment."""
    return on_terminal() and not paths.prompts_off()


def ttl_setting(explicit: int | None = None) -> int:
    """Seconds an unlocked entry is kept: --ttl, else $WITHSECRETS_TTL, else two hours."""
    if explicit is not None:
        return min(explicit, agent.MAX_TTL)             # what the agent will keep, so what is announced
    try:
        value = int(os.environ.get("WITHSECRETS_TTL", DEFAULT_TTL))
    except ValueError:
        return DEFAULT_TTL
    return min(value, agent.MAX_TTL) if value > 0 else DEFAULT_TTL


# ------------------------------------------------------------------ commands
def cmd_init(args: list[str]) -> int:
    slot = piv.parse_slot(args[args.index("--slot") + 1]) if "--slot" in args else 0x9D
    t = piv.open_transport()
    try:
        with piv.exclusive(t):
            pub = piv.slot_public_key(t, slot)
        reader = t.name
    finally:
        t.close()
    if pub is None:
        raise Fail(f"slot {piv.slot_name(slot)} has no certificate; see `pivcard mkcert`")
    pub33 = tagfmt.public_key_to_compressed(pub)
    identity = tagfmt.encode_identity(slot, pub33)
    path = identity_file()
    if path.is_file() and identity not in path.read_text() and "--force" not in args:
        raise Fail(f"{path} already holds a different identity. Entries sealed to it will not open with this "
                   "card. Use --force to replace it.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# PIV card in {reader}, slot {piv.slot_name(slot)}. This file holds no secret.\n"
                    f"# recipient: {tagfmt.encode_recipient(pub33, tagfmt.TAG_RECIPIENT_HRP)}\n{identity}\n")
    print(f"withsecrets: identity written to {path}")
    return 0


def cmd_set(args: list[str]) -> int:
    if not args:
        raise Fail("usage: withsecrets set <entry> <NAME>...   (values typed at a hidden prompt)\n"
                   "       withsecrets set <entry>             (KEY=VALUE lines on standard input)", EXIT_USAGE)
    name, keys, path = args[0], args[1:], entry_file(args[0])
    if keys:                                           # typed, not echoed: nothing in scrollback or history
        if any(not PAIR.fullmatch(key + "=") for key in keys):
            raise Fail("variable names are letters, digits and _ (not starting with a digit)", EXIT_USAGE)
        if not on_terminal():
            raise Fail("typing values needs a terminal. Without one, pipe KEY=VALUE lines to: "
                       f"withsecrets set {name}", EXIT_USAGE)
        text = ""
        for key in keys:
            value = getpass.getpass(f"Value for {key} (not shown): ")
            if not value:
                raise Fail(f"no value entered for {key}; nothing was written", EXIT_USAGE)
            text += f"{key}={value}\n"
    else:
        if sys.stdin.isatty():
            print("Paste KEY=VALUE lines (they will be visible), then end with Ctrl-D (Ctrl-Z Enter on Windows):",
                  file=sys.stderr)
        text = sys.stdin.read()
    pairs, ignored = parse_pairs(text)
    if not pairs:
        raise Fail("no KEY=VALUE line given; nothing was written", EXIT_USAGE)
    refuse_loader_variables(name, pairs, EXIT_USAGE)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".age.tmp")
    to = ["-i", str(_need_identity())]
    if recipients_file().is_file():
        to += ["-R", str(recipients_file())]
    proc = subprocess.run([_age(), "-e", *to, "-o", str(tmp)],
                          input=text.encode(), env=_age_env(), check=False)
    if proc.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise Fail(f"age could not encrypt {name}")
    os.replace(tmp, path)
    with contextlib.suppress(agent.AgentUnavailable):
        agent.control({"op": "clear", "name": name})     # an older unlocked copy would now be stale
    note = f" ({ignored} line(s) that are not KEY=VALUE were stored but will be ignored)" if ignored else ""
    if recipients_file().is_file():
        note += f"; also readable by the recipients in {recipients_file().name}"
    print(f"withsecrets: {name} saved with {len(pairs)} variable(s): {', '.join(k for k, _ in pairs)}{note}",
          file=sys.stderr)
    return 0


def refuse_loader_variables(name: str, pairs: list[tuple[str, str]], status: int = 1) -> None:
    bad = sorted({key for key, _ in pairs if LOADER_VARIABLE.match(key.upper())})
    if bad:
        raise Fail(f"{name} sets {', '.join(bad)}, which would change what programs load. An entry holds "
                   "secrets, not such settings. Nothing was done.", status)


def cmd_unlock(args: list[str]) -> int:
    usage = "usage: withsecrets unlock <entry>... [--ttl SECONDS]"
    ttl = None
    if "--ttl" in args:
        i = args.index("--ttl")
        try:
            ttl, args = int(args[i + 1]), args[:i] + args[i + 2:]
        except (IndexError, ValueError):
            raise Fail(usage, EXIT_USAGE) from None
        if ttl <= 0:
            raise Fail("--ttl is a positive number of seconds", EXIT_USAGE)
    if not args:
        raise Fail(usage, EXIT_USAGE)
    for name in args:
        entry_file(name)                                # validate every name before the card is used
    if paths.prompts_off():
        raise Fail("PIN prompts are switched off here (PIVCARD_NO_PROMPT is set). Unlock in your own "
                   "terminal. Nothing was sent to the card.", EXIT_LOCKED)
    if not can_prompt():
        raise Fail("unlock needs your terminal for the card PIN; nothing was sent to the card", EXIT_LOCKED)
    ttl = ttl_setting(ttl)
    for name in args:
        hit = cached(name)
        if hit is not None:
            print(f"withsecrets: {name} already unlocked ({hit[1] // 60} min left)", file=sys.stderr)
            continue
        hold(name, decrypt(name), ttl)
        print(f"withsecrets: {name} stays unlocked for {ttl // 60} min (withsecrets lock to forget)",
              file=sys.stderr)
    return 0


def cmd_status(args: list[str]) -> int:
    try:
        secrets = agent.control({"op": "status"}).get("secrets", [])
    except agent.AgentUnavailable:
        secrets = []
    for s in secrets:
        print(f"{s['name']}: unlocked, {s['seconds_left'] // 60} min left")
    if not secrets:
        print("nothing unlocked")
    return 0


def cmd_lock(args: list[str]) -> int:
    if len(args) > 1:
        raise Fail("usage: withsecrets lock [<entry>]", EXIT_USAGE)
    with contextlib.suppress(agent.AgentUnavailable):
        agent.control({"op": "clear", "name": args[0] if args else None})
    print(f"withsecrets: locked{' ' + args[0] if args else ''}", file=sys.stderr)
    return 0


def cmd_list(args: list[str]) -> int:
    if len(args) != 1:
        raise Fail("usage: withsecrets list <entry>", EXIT_USAGE)
    for key, _ in parse_pairs(unlocked(args[0]))[0]:
        print(key)
    return 0


def cmd_run(args: list[str]) -> int:
    """Run a command with the variables of unlocked entries. This never asks for a PIN and never touches
    the card: unlocking is a separate act, `withsecrets unlock`. (`--cached-only` is accepted for
    scripts written when this command could prompt.)"""
    while args and args[0] == "--cached-only":
        args = args[1:]
    if "--" not in args:
        raise Fail(__doc__, EXIT_USAGE)
    split = args.index("--")
    entries, command = args[:split], args[split + 1:]
    if not entries or not command or any(e.startswith("-") for e in entries):
        raise Fail(__doc__, EXIT_USAGE)
    env = dict(os.environ)
    found = 0
    for name in entries:                               # every entry must load, or nothing runs
        pairs, _ = parse_pairs(unlocked(name))
        refuse_loader_variables(name, pairs)
        env.update(pairs)
        found += len(pairs)
    if not found:
        raise Fail(f"no KEY=VALUE lines found in: {' '.join(entries)}")
    exe = paths.find_program(command[0])               # on Windows: not from the current directory
    if exe is None:
        raise Fail(f"command not found: {command[0]}", 127)
    if paths.WINDOWS:                                  # exec does not replace the process on Windows
        return subprocess.call([exe, *command[1:]], env=env)
    sys.stdout.flush()                                 # the command replaces this process: nothing printed
    sys.stderr.flush()                                 # so far may be left behind in a buffer
    os.execve(exe, command, env)                       # values travel in the environment, never in argv
    return 0  # pragma: no cover


COMMANDS = {"init": cmd_init, "set": cmd_set, "unlock": cmd_unlock, "status": cmd_status, "lock": cmd_lock,
            "list": cmd_list, "--status": cmd_status, "--lock": cmd_lock, "--list": cmd_list}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    paths.harden_process()                              # this process handles decrypted entries
    try:
        if not argv or argv[0] in ("-h", "--help"):
            print(__doc__)
            return 0 if argv else EXIT_USAGE
        if argv[0] in COMMANDS and "--" not in argv:
            return COMMANDS[argv[0]](argv[1:])
        return cmd_run(argv)
    except Fail as e:
        print(f"withsecrets: {e}" if "\n" not in str(e) else str(e), file=sys.stderr)
        return e.status
    except (CardError, tagfmt.FormatError, agent.AgentNotOurs) as e:
        print(f"withsecrets: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
