# Setting up the card

The tools need two things on the card:

| Slot | Key | Used for |
|---|---|---|
| 9D (key management) | ECC P-256, generated on the card | Decrypting the API token |
| 9A (authentication) | ECC P-256, generated on the card, allowed to sign | SSH logins |

Each slot also needs a certificate. A PIV card has no "read public key" command: the public key is
returned once, when the key is generated, and afterwards only through the certificate stored in the slot.
The tools read that certificate (no PIN needed) to learn the public key and to recognise your card.
`pivcard mkcert` writes a placeholder certificate that carries the public key and asserts nothing.

## With a Cryptnox PIV card

Use the card's own tool, `cryptnox-id` (Python package
[`cryptnox-id-cli`](https://github.com/cryptnox/cryptnox-id-cli)).

> **Read this first: `--default-keys` is for trials only.** The commands below go through the card's
> administration keys. `--default-keys` tells the tool to use the publicly known GlobalPlatform test
> keys, which is what our test cards accepted, and to set the card's PIV management key to its published
> value as well. **With such keys, any program can set a new PIN without knowing the old one, and then
> use the card.** That is fine for trying this out. Before a card guards anything real, replace both with
> keys that only you hold. See the card tool's documentation.

```sh
R="<your reader name>"       # `pivcard readers` prints the names
```

### 1. Only for a blank card: structure, PIN and PUK

These four commands lay down the card's structure and set the PIN and the PUK (the longer code that
unblocks the card after too many wrong PINs). The structure is permanent. Use the tool's `ssh` profile:
in it slot 9A is allowed to sign, which SSH needs. According to the card tool, its default profile gives
9A the authentication role only.

```sh
cryptnox-id --reader "$R" piv perso load-config --profile ssh --default-keys
cryptnox-id --reader "$R" piv perso set-mgmt-key --default-keys
cryptnox-id --reader "$R" piv perso set-pin --default-keys     # asks for the new PIN (6 to 8 digits)
cryptnox-id --reader "$R" piv perso set-puk --default-keys     # asks for the new PUK (8 digits)
```

These are the command names of `cryptnox-id` 1.3 and later. In 1.2 and older, the first two were
`factory piv preperso load-config` and `factory piv preperso set-mgmt-key`.

### 2. The two keys and their certificates

The private keys are generated on the card and never leave it. `generate-key` replaces whatever key was
in the slot, for good.

```sh
cryptnox-id --reader "$R" piv perso generate-key --slot 9D --default-keys --out 9d.pub.pem
pivcard mkcert 9d.pub.pem 9d.cert.pem
cryptnox-id --reader "$R" piv perso import-cert --slot 9D --default-keys --cert 9d.cert.pem

cryptnox-id --reader "$R" piv perso generate-key --slot 9A --default-keys --out 9a.pub.pem
pivcard mkcert 9a.pub.pem 9a.cert.pem --usage sign
cryptnox-id --reader "$R" piv perso import-cert --slot 9A --default-keys --cert 9a.cert.pem
```

Both starting points were tested: a blank card set up with exactly these commands, and a card that was
already personalised.

Versions of the card tool this was tested with: every command above with `cryptnox-id` 1.1.0, on Linux;
every command from `set-pin` on with 1.2.0 as well, on Linux and on Windows. The first two commands can
run only once per card and need a blank one, so they were not repeated with 1.2.0.

## With another PIV card or token

Use its own tool to do the same two things for each slot: generate an ECC P-256 key on the card, and store
a certificate for it. Only standard PIV commands are used afterwards, so other cards should work, but none
has been tested. `pivcard check` tells you.

## Tell the tools which reader to use

`pivcard` never guesses between two cards. With a single card present and no reader chosen, it uses that
card. Once you have chosen a reader with `pivcard use`, it talks to no other.

```sh
pivcard readers              # lists readers without connecting to any card
pivcard use "ACR 38U"        # any part of the reader's name
pivcard status               # PIN state and the keys the card shows; no PIN needed
```

## Check the card

This asks for the PIN, has the card decrypt one test value and make one signature, and confirms that the
card is locked again after each. Run it once with a new card. It sends the PIN to the card in the chosen
reader, so look at `pivcard status` first. If the tools are already set up with another card, they refuse
this one; add `--new-card` to test it on purpose.

```console
$ pivcard check
reader: ACS ACR 38U-CCID 01 00
PIN for the PIV card:
  ok    slot 9D decrypts an age file key
  ok    the card is locked again afterwards
  ok    slot 9A signs for SSH
  ok    the card is locked again afterwards
this card works with these tools
```

## Write the identity file

It holds the card's public key and no secret. From then on the tools recognise your card by it.

```sh
withsecrets init
```
