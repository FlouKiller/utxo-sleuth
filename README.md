# utxo-sleuth

Start from one Bitcoin address, follow its transactions and link the addresses
likely owned by the same entity. Every link carries a confidence score and the
reasons behind it. The output is a set of probabilities, never proof of ownership.

## Install

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e .[dev]
```

## Usage

```bash
utxo-sleuth <address> --json out.report.json --dot out.dot
```

The addresses you trace are sent to the configured API. For anything sensitive,
point `--api` at your own electrs instance. Responses are cached in
`~/.cache/utxo-sleuth/`.

| Option | Purpose |
| --- | --- |
| `--max-hops` | Distance from the seed (default 3) |
| `--min-confidence` | Drop addresses below this score (default 0.3) |
| `--change-threshold` | Probability needed to accept a change output (default 0.7) |
| `--max-addresses`, `--max-requests` | Hard limits; the report says when one was hit |
| `--max-address-txs`, `--max-inputs` | Above these, assume a service and stop |
| `--update-labels` | Download exchange address lists (see below) |
| `--tags` | JSON file `{"address": "service name"}`: never expand these |
| `--truth` | Text file of known addresses: prints precision and recall |

## Exchanges and services

```bash
utxo-sleuth --update-labels
```

This downloads WalletExplorer's address lists for 17 exchanges into
`~/.cache/utxo-sleuth/labels.sqlite`. They stay out of the repository because the
site states no redistribution terms. Lookups are then offline.

The report lists each cluster address that received from or sent to a known
service. It flags a payout as an `unknown service` from 10 outputs, or from 5 when
the sender pays itself back or has at least 50 transactions. Dealing with an
exchange creates no ownership link: only spending together with a labelled
address does.

Coverage is partial. Most WalletExplorer names date from 2016 and its big hot
wallets are often unnamed, so a missing label proves nothing. Coinbase has no
list. `known_services.json` holds checked additions, and `--tags` adds your own.

## How addresses get linked

Confidence multiplies along a path, so doubt grows with distance.

| Link | Confidence | Logic |
| --- | --- | --- |
| Common inputs | 0.95 | Spending together needs every key. This forms the **core** |
| Consolidation | 0.75 | Several inputs to one output |
| Change | 0.70 or more | Bayesian score, see below |
| Sweep | 0.50 | One input to one output, may also be a deposit |

Change scoring starts every output with equal weight, adds a "no change"
hypothesis, and multiplies by a likelihood ratio for each signal: round amounts
(multiples of 1,000 sats), script type matching the inputs, unnecessary inputs,
funding before the transaction, the wallet fingerprint of the spending
transaction, a later sweep into a large consolidation, and funds coming back to
the sender. These ratios are uncalibrated starting guesses in `heuristics.py`.

Each reason in the report starts with `+` if it supports the link and `-` if it
goes against it.

## Avoiding cluster collapse

One false link can pull in an exchange's whole cluster, so the trace stops at
tagged services, very busy addresses and multisig addresses, which may be shared.
It ignores anything shaped like a CoinJoin and huge input sets, and enforces
limits on hops, confidence, addresses and requests.

PayJoin is undetectable and breaks the common-input assumption.

## Measuring accuracy

Run a trace on a wallet whose addresses you know:

```bash
utxo-sleuth <address> --truth wallet.truth.txt
```

Or derive the wallet's addresses offline from its account-level public key:

```bash
utxo-sleuth --xpub-file wallet.xpub --summary
```

- Without an address, the trace starts from the wallet's first used address.
- An extended public key cannot spend, but it reveals the wallet's whole history.
  Keep it in a local file and never share it.
- The tool refuses a file containing a private key, and refuses a seed address
  outside the wallet before making any request.
- Derived addresses are compared locally. Only addresses reached by the trace
  are sent to the API.
- This mode reports precision only, overall and per link kind: a derived list
  includes unused addresses, so recall would mean nothing.
- `--summary` prints counts with no address or txid, so the result is safe to share.
- One key covers one account. An address from another of your accounts counts as
  a false positive.

`.gitignore` covers `*.xpub`, `*.xpub.txt`, `*.truth.txt`, `*.local.json`,
`*.report.json`, `*.dot`, `reports/` and `truth/`, so real addresses stay out of
the repository.

## Tests

```bash
.venv/Scripts/python -m pytest
```
