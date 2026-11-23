"""Card-layer tests against the in-memory PIV card: what is sent, in which order, and what is not."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import run_plugin
from pivcard import apdu, piv
from pivcard import tagfmt as t
from pivcard.apdu import ReaderInfo
from pivcard.fake import SoftCard
from pivcard.plugin import CardError, PinError, Stanza


def peer():
    key = ec.generate_private_key(ec.SECP256R1())
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return key, point


def expected(card, slot, peer_key):
    return peer_key.exchange(ec.ECDH(), card.keys[slot].public_key())


@pytest.fixture
def card():
    c = SoftCard()
    c.pub = c.add_key(0x9D)
    return c


# ---------------------------------------------------------------- opening a card: no PIN, key must match
def test_open_card_checks_the_key_from_the_certificate_without_a_pin(card):
    session = piv.open_card(0x9D, card.pub, transport=card)
    assert session.describe() == "soft reader (slot 9D)" and card.verify_attempts == 0


def test_a_card_with_a_different_key_never_receives_the_pin(card):
    stranger = SoftCard()
    other = stranger.add_key(0x9D)
    with pytest.raises(CardError, match=r"different key.*No PIN was sent"):
        piv.open_card(0x9D, other, transport=card)
    assert card.verify_attempts == 0 and card.closed == "leave"


def test_no_certificate_or_wrong_kind_of_slot_is_refused():
    bare = SoftCard()
    pub = bare.add_key(0x9D, cert=False)
    with pytest.raises(CardError, match="no certificate in slot 9D"):
        piv.open_card(0x9D, pub, transport=bare)
    with pytest.raises(CardError, match="not a key-management slot"):
        piv.open_card(0x9A, pub, transport=bare)
    with pytest.raises(CardError, match="no PIV application"):
        piv.open_card(0x9D, pub, transport=SoftCard(has_piv=False))


def test_compressed_certificates_and_retired_slots_work():
    c = SoftCard()
    pub = c.add_key(0x82, compress=True)
    assert piv.open_card(0x82, pub, transport=c).slot == 0x82


# ---------------------------------------------------------------- using the PIN
def test_ecdh_is_verify_then_operation_then_logout_inside_one_transaction(card):
    key, point = peer()
    session = piv.open_card(0x9D, card.pub, transport=card)
    before, sent = card.transactions, len(card.log)
    assert session.ecdh("123456", point) == expected(card, 0x9D, key)
    assert not card.verified and not card.in_transaction and card.transactions == before + 1
    ins = [a[1] for a in card.log[sent:]]
    assert ins == [0xA4, 0xCB, 0x20, 0x20, 0x87, 0x20, 0x20]  # select, key check, status, VERIFY, ECDH, logout, status
    assert card.verify_attempts == 1 and piv.pin_tries(card) == 6
    session.close()
    assert card.closed == "leave"


def test_wrong_pin_costs_one_try_and_leaves_the_card_locked(card):
    _, point = peer()
    session = piv.open_card(0x9D, card.pub, transport=card)
    with pytest.raises(PinError) as e:
        session.ecdh("000000", point)
    assert e.value.tries_left == 5 and not card.verified and not card.in_transaction


@pytest.mark.parametrize("pin", ["12345", "123456789", "12a456", "", "\uff11\uff12\uff13\uff14\uff15\uff16"])
def test_a_malformed_pin_is_never_sent(card, pin):
    _, point = peer()
    session = piv.open_card(0x9D, card.pub, transport=card)
    with pytest.raises(CardError, match="was not sent"):
        session.ecdh(pin, point)
    assert card.verify_attempts == 0 and card.tries == 6


def test_the_last_pin_try_is_never_used(card):
    _, point = peer()
    card.tries = 1
    session = piv.open_card(0x9D, card.pub, transport=card)
    with pytest.raises(CardError, match="only 1 PIN try left"):
        session.ecdh("123456", point)
    assert card.verify_attempts == 0 and card.tries == 1
    card.tries = 2                                          # one typing mistake on a three-try card: still usable
    assert len(session.ecdh("123456", point)) == 32 and card.tries == card.max_tries


def test_blocked_pin_is_reported(card):
    _, point = peer()
    card.tries = 0
    with pytest.raises(CardError, match="the PIN is blocked"):
        piv.open_card(0x9D, card.pub, transport=card).ecdh("123456", point)
    assert card.verify_attempts == 0


def test_status_query_costs_no_try(card):
    piv.select(card)
    assert [piv.pin_tries(card) for _ in range(5)] == [6] * 5 and card.verify_attempts == 0


# ---------------------------------------------------------------- logging out
def test_logout_falls_back_to_leaving_the_applet_when_reset_is_unsupported():
    c = SoftCard(supports_reset=False)
    pub = c.add_key(0x9D)
    key, point = peer()
    session = piv.open_card(0x9D, pub, transport=c)
    assert session.ecdh("123456", point) == expected(c, 0x9D, key)
    assert not c.verified and c.selected                   # logged out, PIV selected again
    session.close()
    assert c.closed == "leave"


def test_card_is_reset_on_close_when_it_cannot_be_logged_out():
    c = SoftCard(supports_reset=False, supports_deselect=False)
    pub = c.add_key(0x9D)
    _, point = peer()
    session = piv.open_card(0x9D, pub, transport=c)
    session.ecdh("123456", point)
    # Neither logout worked, so the transaction itself ended with a card reset: there was no moment at
    # which another program could have reached the card while it was still verified.
    assert c.ended == "reset" and not c.verified and not c.in_transaction
    session.close()
    assert c.closed == "reset"


def test_a_card_left_unlocked_by_someone_else_is_logged_out_even_on_failure(card):
    _, point = peer()
    piv.select(card)
    piv.verify_pin(card, "123456")                          # another program left the card verified
    session = piv.open_card(0x9D, card.pub, transport=card)
    with pytest.raises(CardError, match="was not sent"):
        session.ecdh("bad", point)
    assert not card.verified and card.verify_attempts == 1  # only the other program's VERIFY carried a PIN


def test_ecdh_without_verify_is_refused_by_the_card(card):
    _, point = peer()
    piv.select(card)
    with pytest.raises(CardError, match="security status not satisfied"):
        piv.ecdh(card, 0x9D, point)


# ---------------------------------------------------------------- choosing a reader
YUBI = ReaderInfo("Vendor Token 00 00", True, b"\x3b")
ACS = ReaderInfo("ACS Reader 01 00", True, b"\x3b")
EMPTY = ReaderInfo("Empty Reader 02 00", False, b"")


def test_single_card_is_used_but_two_cards_are_never_guessed():
    assert apdu.pick_reader([ACS, EMPTY], None) is ACS
    with pytest.raises(CardError, match="Refusing to guess"):
        apdu.pick_reader([YUBI, ACS], None)
    with pytest.raises(CardError, match="no smart card found"):
        apdu.pick_reader([EMPTY], None)


def test_named_reader_is_matched_by_substring():
    assert apdu.pick_reader([YUBI, ACS], "ACS") is ACS
    with pytest.raises(CardError, match="no reader matches"):
        apdu.pick_reader([YUBI, ACS], "Nitro")
    with pytest.raises(CardError, match="matches 2 readers"):
        apdu.pick_reader([YUBI, ACS], "0")
    with pytest.raises(CardError, match="no card in reader"):
        apdu.pick_reader([ACS, EMPTY], "Empty")


def test_reader_setting_comes_from_env_then_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("PIVCARD_READER", raising=False)
    assert apdu.configured_reader() is None
    (tmp_path / "pivcard").mkdir()
    (tmp_path / "pivcard" / "reader").write_text("ACS Reader\n")
    assert apdu.configured_reader() == "ACS Reader"
    monkeypatch.setenv("PIVCARD_READER", "Other")
    assert apdu.configured_reader() == "Other"


# ---------------------------------------------------------------- plugin + card layer together
def test_plugin_decrypts_through_the_card_layer(card):
    args, body = t.wrap(bytes(range(16)), card.pub)
    rc, seen = run_plugin(
        "identity-v1",
        [Stanza("add-identity", [t.encode_identity(0x9D, card.pub)]),
         Stanza("recipient-stanza", ["0", t.STANZA, *args], body)],
        lambda st: Stanza("ok", [], b"123456") if st.tag == "request-secret" else Stanza("ok", []),
        lambda slot, pub: piv.open_card(slot, pub, transport=card))
    assert rc == 0 and [(s.tag, s.body) for s in seen[1:]] == [("file-key", bytes(range(16)))]
    assert b"soft reader (slot 9D)" in seen[0].body
    assert not card.verified and card.closed == "leave" and card.verify_attempts == 1


def test_plugin_with_no_terminal_sends_no_verify_to_the_card(card):
    args, body = t.wrap(bytes(16), card.pub)
    rc, seen = run_plugin(
        "identity-v1",
        [Stanza("add-identity", [t.encode_identity(0x9D, card.pub)]),
         Stanza("recipient-stanza", ["0", t.STANZA, *args], body)],
        lambda st: Stanza("fail", []) if st.tag == "request-secret" else Stanza("ok", []),
        lambda slot, pub: piv.open_card(slot, pub, transport=card))
    assert rc == 0 and seen[-1].tag == "error" and card.verify_attempts == 0 and card.tries == 6


# ---------------------------------------------------------------- signing (the SSH key) and card swaps
def test_sign_is_one_unit_and_verifies(card):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils
    pub = card.add_key(0x9A)
    session = piv.open_key(0x9A, pub, transport=card)
    digest = bytes(range(32))
    signature = session.sign("123456", digest)
    card.keys[0x9A].public_key().verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    assert not card.verified and card.verify_attempts == 1


def test_check_pin_verifies_and_logs_out(card):
    session = piv.open_key(0x9D, card.pub, transport=card)
    session.check_pin("123456")
    assert not card.verified
    with pytest.raises(PinError):
        session.check_pin("654321")
    assert card.tries == 5


def test_a_card_swapped_after_opening_does_not_receive_the_pin(card):
    _, point = peer()
    session = piv.open_card(0x9D, card.pub, transport=card)
    card.add_key(0x9D)                                      # the "card" now holds another key
    with pytest.raises(CardError, match="different key"):
        session.ecdh("123456", point)
    assert card.verify_attempts == 0


# ---------------------------------------------------------------- `pivcard check`
@pytest.fixture
def check(monkeypatch, tmp_path):
    from pivcard import tool
    for name in ("XDG_CONFIG_HOME", "APPDATA"):                 # no setup of the real user is read
        monkeypatch.setenv(name, str(tmp_path / "config"))
    monkeypatch.delenv("WITHSECRETS_HOME", raising=False)
    monkeypatch.delenv("PIVCARD_NO_PROMPT", raising=False)

    def run(card, pin="123456", *extra):
        monkeypatch.setattr(tool.piv, "open_transport", lambda reader=None: card)
        monkeypatch.setattr(tool.sys, "stdin", type("Tty", (), {"isatty": staticmethod(lambda: True)})())
        monkeypatch.setattr(tool.getpass, "getpass", lambda prompt="": pin)
        return tool.main(["check", *extra])

    return run


def test_check_passes_on_a_good_card_and_leaves_it_locked(check, capsys):
    card = SoftCard()
    card.add_key(0x9D)
    card.add_key(0x9A)
    assert check(card) == 0
    out = capsys.readouterr().out
    assert out.count("  ok  ") == 4 and "this card works" in out and "reset" not in out
    assert not card.verified and card.tries == 6


def test_check_reports_a_card_that_only_locks_by_reset_and_skips_an_empty_slot(check, capsys):
    card = SoftCard(supports_reset=False, supports_deselect=False)
    card.add_key(0x9D)
    assert check(card) == 0
    out = capsys.readouterr().out
    assert "needed a card reset" in out and "skip  slot 9A" in out and not card.verified


def test_check_with_a_wrong_pin_costs_exactly_one_try(check, capsys):
    card = SoftCard()
    card.add_key(0x9D)
    card.add_key(0x9A)
    assert check(card, pin="000000") == 1
    assert "wrong PIN" in capsys.readouterr().err and card.tries == 5 and card.verify_attempts == 1


def test_check_fails_when_the_certificate_is_for_another_key(check, capsys):
    card = SoftCard()
    card.add_key(0x9D)
    other = SoftCard()
    other.add_key(0x9D)
    card.keys[0x9D] = other.keys[0x9D]                  # the certificate no longer matches the private key
    assert check(card) == 1
    assert "FAIL  slot 9D" in capsys.readouterr().out and not card.verified


# ---------------------------------------------------------------- nothing may cut the logout short
def test_a_stop_signal_during_the_pin_check_still_ends_with_a_logout(card):
    """The signal arrives while VERIFY is on its way to the card. It is held back until the card has been
    logged out, and only then ends the program."""
    import signal

    from pivcard import plugin

    class Interrupted(type(card)):
        def transmit(self, apdu):
            if apdu[1] == 0x20 and apdu[2] == 0x00 and len(apdu) > 5 and not self.__dict__.get("fired"):
                self.fired = True
                signal.raise_signal(signal.SIGTERM)
            return super().transmit(apdu)

    card.__class__ = Interrupted
    _, point = peer()
    before = signal.getsignal(signal.SIGTERM)
    try:
        plugin._exit_cleanly_on_signals()                       # what the plugin installs: exit on SIGTERM
        session = piv.open_card(0x9D, card.pub, transport=card)
        with pytest.raises(SystemExit) as stopped:
            session.ecdh("123456", point)
        assert stopped.value.code == 128 + signal.SIGTERM
        assert card.fired and card.verify_attempts == 1 and not card.verified and not card.in_transaction
        assert signal.getsignal(signal.SIGTERM) is not before   # the plugin's own handler is back in place
    finally:
        signal.signal(signal.SIGTERM, before)


def test_signals_are_only_held_in_the_main_thread_and_handlers_are_restored():
    import signal
    import threading
    before = signal.getsignal(signal.SIGINT)
    with piv.uninterrupted():
        assert signal.getsignal(signal.SIGINT) is not before
    assert signal.getsignal(signal.SIGINT) is before
    seen = []
    worker = threading.Thread(target=lambda: [seen.append(signal.getsignal(signal.SIGINT)) for _ in [0]
                                              if piv.uninterrupted().__enter__() is None])
    worker.start()
    worker.join()
    assert seen == [before]                                     # in a worker thread nothing is touched


# ---------------------------------------------------------------- the PC/SC transport's two retry rules
def scripted_transport(answers):
    t = object.__new__(apdu.PcscTransport)
    sent = []

    def raw(command):
        sent.append(bytes(command))
        return answers[min(len(sent), len(answers)) - 1]

    t._raw = raw
    return t, sent


def test_only_a_command_that_ends_with_a_length_byte_is_resent_with_another_length():
    verify = bytes([0x00, 0x20, 0x00, 0x80, 0x08]) + b"123456\xff\xff"
    t, sent = scripted_transport([(b"", 0x6C08), (b"", 0x9000)])
    assert t.transmit(verify) == (b"", 0x6C08) and sent == [verify]          # a PIN is never sent twice
    read = bytes([0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x0B, 0x00])
    t, sent = scripted_transport([(b"", 0x6C10), (b"data", 0x9000)])
    assert t.transmit(read) == (b"data", 0x9000) and sent == [read, read[:-1] + b"\x10"]
    assert apdu._ends_with_le(bytes(5)) and not apdu._ends_with_le(bytes(4)) and not apdu._ends_with_le(verify)


def test_a_card_that_never_stops_announcing_more_data_is_given_up_on():
    t, sent = scripted_transport([(b"x", 0x6110)])
    with pytest.raises(CardError, match="keeps announcing"):
        t.transmit(bytes([0x00, 0xCB, 0x3F, 0xFF, 0x00]))
    assert len(sent) == 1 + apdu.MAX_RESPONSE_PARTS


def test_check_sends_the_pin_only_to_the_card_that_was_set_up(check, capsys, monkeypatch):
    from pivcard import agent as ag
    from pivcard import tagfmt, tool
    from pivcard import withsecrets as ws
    mine = SoftCard()
    pub_9d, pub_9a = mine.add_key(0x9D), mine.add_key(0x9A)
    ws.identity_file().parent.mkdir(parents=True)
    ws.identity_file().write_text("# comment\n" + tagfmt.encode_identity(0x9D, pub_9d) + "\n")
    tool.ssh_key_file().parent.mkdir(parents=True)
    tool.ssh_key_file().write_text(ag.ssh_public_key_line(pub_9a) + "\n")
    assert check(mine) == 0                                     # the card these files describe
    capsys.readouterr()

    other = SoftCard()
    other.add_key(0x9D)
    other.add_key(0x9A)
    assert check(other) == 1
    said = capsys.readouterr().err
    assert "not the card these tools were set up with" in said and "--new-card" in said
    assert other.verify_attempts == 0 and other.tries == 6
    half = SoftCard()                                           # the right 9D key, another 9A key
    half.add_key(0x9D, mine.keys[0x9D])
    half.add_key(0x9A)
    assert check(half) == 1 and half.verify_attempts == 0
    assert check(other, "123456", "--new-card") == 0 and other.verify_attempts == 2


@pytest.mark.parametrize("damage", ["empty identity", "indented lower case", "truncated", "not utf-8",
                                    "one word key", "ed25519 key"])
def test_a_damaged_record_of_the_card_stops_the_check_before_any_pin(check, capsys, damage):
    from pivcard import agent as ag
    from pivcard import tagfmt, tool
    from pivcard import withsecrets as ws
    mine = SoftCard()
    identity = tagfmt.encode_identity(0x9D, mine.add_key(0x9D))
    key_line = ag.ssh_public_key_line(mine.add_key(0x9A))
    ws.identity_file().parent.mkdir(parents=True)
    tool.ssh_key_file().parent.mkdir(parents=True)
    ws.identity_file().write_text(identity + "\n")
    tool.ssh_key_file().write_text(key_line + "\n")
    if damage == "empty identity":
        ws.identity_file().write_text("# nothing here\n")
    elif damage == "indented lower case":
        ws.identity_file().write_text("   " + identity.lower() + "\n")
    elif damage == "truncated":
        ws.identity_file().write_text(identity[:-6] + "\n")
    elif damage == "not utf-8":
        ws.identity_file().write_bytes(b"\xff\xfe\x00garbage\n")
    elif damage == "one word key":
        tool.ssh_key_file().write_text("ecdsa-sha2-nistp256\n")
    else:
        tool.ssh_key_file().write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG2M6IoDCRH2P1Qn3zCxZ0sDDYO4TLe5Z4zo1Kb7nCkZ x\n")
    other = SoftCard()
    other.add_key(0x9D)
    other.add_key(0x9A)
    assert check(other) == 1
    assert "No PIN was asked for or sent" in capsys.readouterr().err and other.verify_attempts == 0
    assert check(other, "123456", "--new-card") == 0            # on purpose it can still be tested


def test_check_compares_every_slot_that_was_recorded_for_the_card(check, capsys):
    from pivcard import tagfmt
    from pivcard import withsecrets as ws
    mine = SoftCard()
    mine.add_key(0x9D)
    retired = mine.add_key(0x82)                                # an identity made with `withsecrets init --slot 82`
    ws.identity_file().parent.mkdir(parents=True)
    ws.identity_file().write_text(tagfmt.encode_identity(0x82, retired) + "\n")
    assert check(mine) == 0
    other = SoftCard()
    other.add_key(0x9D)
    other.add_key(0x82)
    assert check(other) == 1 and other.verify_attempts == 0


def test_check_does_nothing_where_pin_prompts_are_switched_off(check, capsys, monkeypatch):
    card = SoftCard()
    card.add_key(0x9D)
    monkeypatch.setenv("PIVCARD_NO_PROMPT", "1")
    assert check(card) == 1 and "PIVCARD_NO_PROMPT" in capsys.readouterr().err and card.log == []
