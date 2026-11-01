import pytest

from conftest import P2PKH, tx
from utxo_sleuth.heuristics import (
    MAX_CHANGE_OUTPUTS,
    OutputFacts,
    change_candidates,
    guess_change,
    looks_like_coinjoin,
)


def payment():
    return tx("t", [("a", 500_000)], [("pay", 100_000), ("rest", 399_123)])


def test_equal_outputs_with_many_inputs_is_a_coinjoin():
    mix = tx(
        "mix",
        [("a", 200_000), ("b", 200_000), ("c", 200_000)],
        [("x", 100_000), ("y", 100_000), ("z", 100_000), ("w", 95_000)],
    )
    assert looks_like_coinjoin(mix)


def test_equal_outputs_from_one_input_is_not_a_coinjoin():
    batch = tx("batch", [("a", 500_000)], [("x", 100_000), ("y", 100_000)])
    assert not looks_like_coinjoin(batch)


def test_different_outputs_are_not_a_coinjoin():
    plain = tx("plain", [("a", 90_000), ("b", 90_000)], [("x", 100_000), ("y", 79_000)])
    assert not looks_like_coinjoin(plain)


def test_no_change_detection_on_payment_back_to_an_input():
    reuse = tx("reuse", [("a", 500_000)], [("x", 100_000), ("a", 399_000)])
    assert change_candidates(reuse) == []


def test_no_change_detection_on_large_batches():
    outputs = [(f"o{i}", 1_000 + i) for i in range(MAX_CHANGE_OUTPUTS + 1)]
    assert change_candidates(tx("batch", [("a", 500_000)], outputs)) == []


def test_a_neutral_transaction_gives_no_guess():
    neutral = tx("t", [("a", 500_000)], [("x", 123_456), ("y", 375_544)])
    assert guess_change(neutral, {}) is None


def test_a_single_heuristic_stays_below_the_threshold():
    assert guess_change(payment(), {}) is None


def test_thousands_of_sats_count_as_round():
    small = tx("t", [("a", 410_321)], [("pay", 27_000), ("rest", 383_204)])
    assert guess_change(small, {}, threshold=0.6).address == "rest"


def test_round_amount_and_script_type_agree_on_the_change():
    typed = tx(
        "t",
        [("a", 500_000)],
        [("pay", 100_000, P2PKH), ("rest", 399_123)],
    )
    guess = guess_change(typed, {})
    assert guess.address == "rest"
    assert guess.vout == 1
    assert guess.probability == pytest.approx(9 / (9 + 0.33**2 + 1))
    assert len(guess.reasons) == 4


def test_reused_payment_address_supports_the_round_amount():
    guess = guess_change(payment(), {0: OutputFacts(reused=True)})
    assert guess.address == "rest"


def test_unnecessary_input_penalises_the_larger_output():
    # If the big output were change, the small payment needed only one input.
    two_inputs = tx(
        "t",
        [("a", 400_000), ("b", 300_000)],
        [("small", 150_123), ("big", 548_877)],
    )
    guess = guess_change(two_inputs, {}, threshold=0.4)
    assert guess.address == "small"
    assert guess.probability == pytest.approx(1 / 2.4)
    assert guess.reasons == ("+ other output: would make an input unnecessary",)


def test_wallet_fingerprint_of_the_next_spend_counts():
    same = payment().fingerprint
    other = tx("n", [("z", 1)], [("q", 1)], version=1, locktime=800_000).fingerprint
    facts = {0: OutputFacts(spender=other), 1: OutputFacts(spender=same)}
    guess = guess_change(payment(), facts)
    assert guess.address == "rest"
    assert "+ spent with the same wallet fingerprint" in guess.reasons
    assert "+ other output: spent with a different wallet fingerprint" in guess.reasons


def test_evidence_against_the_guess_is_marked():
    same = payment().fingerprint
    facts = {0: OutputFacts(reused=True, spender=same)}
    guess = guess_change(payment(), facts)
    assert "- other output: spent with the same wallet fingerprint" in guess.reasons


def test_a_sweep_into_a_service_marks_a_payment():
    facts = {0: OutputFacts(spender_inputs=247)}
    guess = guess_change(payment(), facts)
    assert guess.address == "rest"
    assert any("246 other inputs" in reason for reason in guess.reasons)


def test_funds_coming_back_point_at_the_sender():
    neutral = tx("t", [("a", 500_000)], [("x", 123_456), ("y", 375_544)])
    facts = {0: OutputFacts(returns_to_inputs=True), 1: OutputFacts(reused=True)}
    assert guess_change(neutral, facts).address == "x"
