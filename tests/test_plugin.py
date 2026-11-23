"""Plugin protocol tests against a scripted age client and a software card."""
import io

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import SoftFactory, SoftSession, run_plugin
from pivcard import plugin
from pivcard import tagfmt as t
from pivcard.plugin import Stanza, read_stanza, write_stanza

FILE_KEY = bytes(range(16))


def stanza_for(pub33, file_index=0, file_key=FILE_KEY) -> Stanza:
    args, body = t.wrap(file_key, pub33)
    return Stanza("recipient-stanza", [str(file_index), t.STANZA, *args], body)


def identity(card, slot=0x9D) -> Stanza:
    return Stanza("add-identity", [t.encode_identity(slot, card.pub33)])


def ok_with_pin(pin="123456"):
    return lambda st: Stanza("ok", [], pin.encode()) if st.tag == "request-secret" else Stanza("ok", [])


# ---------------------------------------------------------------- stanza text format
@pytest.mark.parametrize("size", [0, 1, 16, 47, 48, 49, 96, 200])
def test_stanza_bodies_round_trip_at_line_boundaries(size):
    buf = io.BytesIO()
    write_stanza(buf, "cmd", ["a", "b"], bytes(range(256))[:size] * 1)
    text = buf.getvalue().decode()
    assert all(len(line) <= 64 for line in text.splitlines())
    assert len(text.splitlines()[-1]) < 64                      # final line is always short
    buf.seek(0)
    st = read_stanza(buf)
    assert (st.tag, st.args, len(st.body)) == ("cmd", ["a", "b"], size) and read_stanza(buf) is None


def test_malformed_input_is_a_protocol_error():
    for raw in (b"hello\n\n", b"-> x\n", b"-> x\n!!!!\n"):
        with pytest.raises(plugin.ProtocolError):
            read_stanza(io.BytesIO(raw))


# ---------------------------------------------------------------- recipient-v1
def test_encrypt_to_recipients_and_identities(card):
    other = SoftSession(ec.generate_private_key(ec.SECP256R1()))
    rc, seen = run_plugin("recipient-v1", [
        Stanza("add-recipient", [t.encode_recipient(card.pub33)]),
        Stanza("grease-xyz", ["whatever"], b"ignored"),
        identity(other),
        Stanza("wrap-file-key", [], FILE_KEY),
        Stanza("wrap-file-key", [], bytes(16)),
    ])
    assert rc == 0 and [s.tag for s in seen] == ["recipient-stanza"] * 4
    assert sorted(s.args[0] for s in seen) == ["0", "0", "1", "1"]
    first = next(s for s in seen if s.args[0] == "0")
    tag, enc = t.parse(first.args[2:], first.body)
    owner = card if t.is_for(tag, enc, card.pub33) else other
    assert t.unwrap(enc, first.body, owner.pub33, lambda peer: owner.ecdh("123456", peer)) == FILE_KEY


def test_encrypt_reports_bad_recipient_and_emits_no_stanza(card):
    rc, seen = run_plugin("recipient-v1", [
        Stanza("add-recipient", [t.encode_recipient(card.pub33)]),
        Stanza("add-recipient", ["age1pivcard1qqqqqq"]),
        Stanza("wrap-file-key", [], FILE_KEY),
    ])
    assert rc == 0 and [(s.tag, s.args) for s in seen] == [("error", ["recipient", "1"])]


# ---------------------------------------------------------------- identity-v1
def test_decrypt_asks_for_the_pin_once_and_returns_file_keys(card):
    factory = SoftFactory(card)
    rc, seen = run_plugin("identity-v1", [
        identity(card),
        Stanza("recipient-stanza", ["0", "X25519", "abc"], bytes(32)),       # someone else's stanza
        stanza_for(card.pub33, 0),
        stanza_for(card.pub33, 1, bytes(16)),
    ], ok_with_pin(), factory)
    assert rc == 0
    assert [s.tag for s in seen] == ["request-secret", "file-key", "file-key"]
    assert [(s.args, s.body) for s in seen[1:]] == [(["0"], FILE_KEY), (["1"], bytes(16))]
    assert factory.opened == [(0x9D, card.pub33)] and card.verify_calls == 2 and card.closed


def test_no_terminal_means_no_verify_reaches_the_card(card):
    """The client answers `fail` to request-secret (no TTY). Nothing may be sent to the card."""
    factory = SoftFactory(card)
    def respond(st):
        return Stanza("fail", []) if st.tag == "request-secret" else Stanza("ok", [])

    rc, seen = run_plugin("identity-v1", [identity(card), stanza_for(card.pub33)], respond, factory)
    assert rc == 0 and [s.tag for s in seen] == ["request-secret", "error"]
    assert seen[1].args == ["identity", "0"] and b"Nothing was sent to the card" in seen[1].body
    assert card.verify_calls == 0 and card.tries == 6 and card.closed


def test_no_pin_is_asked_for_where_prompts_are_switched_off(card, monkeypatch):
    monkeypatch.setenv("PIVCARD_NO_PROMPT", "1")
    rc, seen = run_plugin("identity-v1", [identity(card), stanza_for(card.pub33)], ok_with_pin(), SoftFactory(card))
    assert rc == 0 and [s.tag for s in seen] == ["error"] and b"PIVCARD_NO_PROMPT" in seen[0].body
    assert card.verify_calls == 0


def test_a_stanza_with_a_point_off_the_curve_is_refused_before_any_pin(card):
    good = stanza_for(card.pub33)
    tag, enc = good.args[1], good.args[2]
    off_curve = t.b64e(b"\x04" + b"\x01" * 64)
    bad = Stanza("recipient-stanza", ["0", "p256tag", tag, off_curve], good.body)
    assert enc != off_curve
    rc, seen = run_plugin("identity-v1", [identity(card), bad], ok_with_pin(), SoftFactory(card))
    assert rc == 0 and "request-secret" not in [s.tag for s in seen] and card.verify_calls == 0
    assert [(s.tag, s.args[0]) for s in seen] == [("error", "stanza")]


def test_stanza_for_someone_else_never_opens_a_card(card):
    stranger = SoftSession(ec.generate_private_key(ec.SECP256R1()))
    factory = SoftFactory(card)
    rc, seen = run_plugin("identity-v1", [identity(card), stanza_for(stranger.pub33)], ok_with_pin(), factory)
    assert rc == 0 and seen == [] and factory.opened == [] and card.verify_calls == 0


def test_wrong_pin_is_reported_once_and_not_retried(card):
    factory = SoftFactory(card)
    rc, seen = run_plugin("identity-v1", [
        identity(card), stanza_for(card.pub33, 0), stanza_for(card.pub33, 1),
    ], ok_with_pin("000000"), factory)
    assert rc == 0 and [s.tag for s in seen] == ["request-secret", "error"]
    assert b"wrong PIN" in seen[1].body and b"5 tries left" in seen[1].body
    assert card.verify_calls == 1 and card.tries == 5          # the second file did not cost a try


def test_card_absent_is_an_identity_error_without_a_pin_prompt(card):
    rc, seen = run_plugin("identity-v1", [identity(card), stanza_for(card.pub33)], ok_with_pin(), SoftFactory())
    assert rc == 0 and [(s.tag, s.args) for s in seen] == [("error", ["identity", "0"])]


def test_invalid_identity_stops_everything(card):
    factory = SoftFactory(card)
    rc, seen = run_plugin("identity-v1", [
        identity(card), Stanza("add-identity", ["AGE-PLUGIN-PIVCARD-1QQQQQQ"]), stanza_for(card.pub33),
    ], ok_with_pin(), factory)
    assert rc == 0 and [(s.tag, s.args) for s in seen] == [("error", ["identity", "1"])]
    assert factory.opened == [] and card.verify_calls == 0


def test_malformed_p256tag_stanza_blocks_that_file_only(card):
    factory = SoftFactory(card)
    good = stanza_for(card.pub33, 1)
    rc, seen = run_plugin("identity-v1", [
        identity(card),
        stanza_for(card.pub33, 0),
        Stanza("recipient-stanza", ["0", t.STANZA, "CXBuUw"], bytes(32)),    # same file, wrong shape
        good,
    ], ok_with_pin(), factory)
    assert rc == 0
    assert [(s.tag, s.args) for s in seen] == [("error", ["stanza", "0", "1"]), ("request-secret", []),
                                               ("file-key", ["1"])]
    assert card.verify_calls == 1


def test_tampered_body_is_a_stanza_error(card):
    st = stanza_for(card.pub33)
    st.body = st.body[:-1] + bytes([st.body[-1] ^ 1])
    rc, seen = run_plugin("identity-v1", [identity(card), st], ok_with_pin(), SoftFactory(card))
    assert rc == 0 and [(s.tag, s.args) for s in seen] == [("request-secret", []), ("error", ["stanza", "0", "0"])]


def test_main_rejects_unknown_state_machine_and_prints_usage(capsys):
    assert plugin.main(["--age-plugin=identity-v9"]) == 1
    assert plugin.main([]) == 2 and plugin.main(["--help"]) == 0
    assert "pivcard identity" in capsys.readouterr().err


def test_a_stop_signal_becomes_a_normal_exit_so_the_card_is_logged_out():
    import os
    import signal

    from pivcard import plugin
    before = signal.getsignal(signal.SIGTERM)
    cleaned = []
    try:
        plugin._exit_cleanly_on_signals()
        with pytest.raises(SystemExit) as stopped:
            try:
                if os.name == "posix":                          # on Windows os.kill ends the process at once
                    os.kill(os.getpid(), signal.SIGTERM)
                signal.raise_signal(signal.SIGTERM)             # in case delivery was not immediate
            finally:
                cleaned.append("logout")                        # what PivSession's `finally` relies on
        assert stopped.value.code == 128 + signal.SIGTERM and cleaned == ["logout"]
    finally:
        signal.signal(signal.SIGTERM, before)
