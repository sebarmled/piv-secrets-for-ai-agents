"""PC/SC transport: one explicitly chosen reader, short APDUs, transactions.

Two rules shape this module:

  * Readers are listed *passively* (name, card present, ATR) without connecting to any card, and a
    reader is never guessed: if more than one reader holds a card, the user must name the one to use.
    Other tokens in other readers are therefore never touched, not even with a SELECT.
  * Only short APDUs are used (with GET RESPONSE chaining), so plain CCID readers without
    extended-length support work.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from .paths import config_dir
from .plugin import CardError


@dataclass(frozen=True)
class ReaderInfo:
    name: str
    present: bool
    atr: bytes


class Transport(Protocol):
    name: str

    def transmit(self, apdu: bytes) -> tuple[bytes, int]: ...
    def begin(self) -> None: ...
    def end(self, reset: bool = False) -> None: ...
    def close(self, reset: bool = False) -> None: ...


def _scard():
    try:
        from smartcard import scard
    except ImportError as e:  # pragma: no cover - depends on the host
        raise CardError(f"pyscard is not installed ({e}); install python3-pyscard") from None
    return scard


def _check(scard, hresult: int, what: str) -> None:
    if hresult != scard.SCARD_S_SUCCESS:
        raise CardError(f"PC/SC {what} failed: {scard.SCardGetErrorMessage(hresult)}")


def list_readers() -> list[ReaderInfo]:
    """Every PC/SC reader with card presence and ATR. Opens no connection to any card."""
    scard = _scard()
    hresult, ctx = scard.SCardEstablishContext(scard.SCARD_SCOPE_USER)
    _check(scard, hresult, "EstablishContext (is pcscd running?)")
    try:
        hresult, names = scard.SCardListReaders(ctx, [])
        if hresult == getattr(scard, "SCARD_E_NO_READERS_AVAILABLE", None) or not names:
            return []
        _check(scard, hresult, "ListReaders")
        hresult, states = scard.SCardGetStatusChange(ctx, 0, [(n, scard.SCARD_STATE_UNAWARE) for n in names])
        _check(scard, hresult, "GetStatusChange")
        return [ReaderInfo(name, bool(state & scard.SCARD_STATE_PRESENT), bytes(atr)) for name, state, atr in states]
    finally:
        scard.SCardReleaseContext(ctx)


def configured_reader() -> str | None:
    """The reader to use: $PIVCARD_READER, else the one saved by `pivcard use`. A substring of the name."""
    wanted = os.environ.get("PIVCARD_READER")
    if wanted:
        return wanted
    try:
        return (config_dir() / "reader").read_text().strip() or None
    except OSError:
        return None


def pick_reader(readers: list[ReaderInfo], wanted: str | None) -> ReaderInfo:
    """Choose the reader to talk to, or refuse. Never guesses between two cards."""
    with_card = [r for r in readers if r.present]
    if wanted:
        hits = [r for r in readers if wanted in r.name]
        if not hits:
            seen = ", ".join(repr(r.name) for r in readers) or "none"
            raise CardError(f"no reader matches {wanted!r} (readers present: {seen})")
        if len(hits) > 1:
            raise CardError(f"{wanted!r} matches {len(hits)} readers: " + ", ".join(repr(r.name) for r in hits))
        if not hits[0].present:
            raise CardError(f"no card in reader {hits[0].name!r}")
        return hits[0]
    if not with_card:
        raise CardError("no smart card found in any reader")
    if len(with_card) > 1:
        names = ", ".join(repr(r.name) for r in with_card)
        raise CardError(f"{len(with_card)} readers hold a card ({names}). Refusing to guess: "
                        "run `pivcard use <reader>` or set PIVCARD_READER.")
    return with_card[0]


MAX_RESPONSE_PARTS = 64                  # a certificate is a few parts of at most 256 bytes


def _ends_with_le(apdu: bytes) -> bool:
    """Does this short command end with an expected-length byte (Le)? Only then may it be rewritten."""
    return len(apdu) == 5 or (len(apdu) > 5 and len(apdu) == 6 + apdu[4])


class PcscTransport:
    """A shared-mode PC/SC connection to one reader."""

    def __init__(self, reader: str):
        self.name = reader
        self._scard = scard = _scard()
        hresult, self._ctx = scard.SCardEstablishContext(scard.SCARD_SCOPE_USER)
        _check(scard, hresult, "EstablishContext")
        hresult, self._card, self._proto = scard.SCardConnect(
            self._ctx, reader, scard.SCARD_SHARE_SHARED, scard.SCARD_PROTOCOL_T0 | scard.SCARD_PROTOCOL_T1)
        if hresult != scard.SCARD_S_SUCCESS:
            scard.SCardReleaseContext(self._ctx)
            _check(scard, hresult, f"Connect to {reader!r}")
        self._in_transaction = False
        self._open = True

    def _raw(self, apdu: bytes) -> tuple[bytes, int]:
        hresult, resp = self._scard.SCardTransmit(self._card, self._proto, list(apdu))
        _check(self._scard, hresult, "Transmit")
        if len(resp) < 2:
            raise CardError("card returned a truncated response")
        return bytes(resp[:-2]), (resp[-2] << 8) | resp[-1]

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        data, sw = self._raw(apdu)
        if sw >> 8 == 0x6C and _ends_with_le(apdu):          # wrong Le: retry with the length the card names
            data, sw = self._raw(apdu[:-1] + bytes([sw & 0xFF]))
        for _ in range(MAX_RESPONSE_PARTS):                  # more data: GET RESPONSE
            if sw >> 8 != 0x61:
                return data, sw
            more, sw = self._raw(bytes([0x00, 0xC0, 0x00, 0x00, sw & 0xFF]))
            data += more
        raise CardError("the card keeps announcing more response data; giving up")

    def begin(self) -> None:
        _check(self._scard, self._scard.SCardBeginTransaction(self._card), "BeginTransaction")
        self._in_transaction = True

    def end(self, reset: bool = False) -> None:
        """End the transaction. With reset=True the card is reset as the transaction ends, so that no other
        program can reach it in between (used when the card would not log out)."""
        if self._in_transaction:
            self._in_transaction = False
            how = self._scard.SCARD_RESET_CARD if reset else self._scard.SCARD_LEAVE_CARD
            self._scard.SCardEndTransaction(self._card, how)

    def close(self, reset: bool = False) -> None:
        if not self._open:
            return
        self._open = False
        self.end()
        how = self._scard.SCARD_RESET_CARD if reset else self._scard.SCARD_LEAVE_CARD
        self._scard.SCardDisconnect(self._card, how)
        self._scard.SCardReleaseContext(self._ctx)
