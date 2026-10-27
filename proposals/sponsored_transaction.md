# EIP: Sponsored Transactions

## Contents

- [Abstract](#abstract)
- [Motivation](#motivation)
- [Specification](#specification)
  - [Parameters](#parameters)
  - [Transaction payload](#transaction-payload)
  - [Sender authorization](#sender-authorization)
  - [Payer authorization](#payer-authorization)
  - [Transaction validity](#transaction-validity)
  - [Gas accounting (state transition)](#gas-accounting-state-transition)
  - [Receipt](#receipt)
  - [Contract payer authorization](#contract-payer-authorization)
- [Test Cases](#test-cases)
- [Rationale](#rationale)
- [Backwards Compatibility](#backwards-compatibility)
- [Security Considerations](#security-considerations)

## Abstract

This EIP introduces a sponsored transaction type, `TX_TYPE` (`0x53`), under EIP-2718. A designated
`payer` funds gas from its `SponsorRegistry` vault, while the `sender` supplies `value` and remains
the transaction origin and the caller of the initial EVM message. The `payer` may be the `sender`.

Sender authorization uses ECDSA. A `payer` with empty account code authorizes gas expenditure with
an ECDSA signature over a separate digest. A `payer` with non-empty code authorizes it through a
contract call.

This EIP specifies the 14-field transaction payload, signing domains, authorization checks, and gas
accounting. The payload carries `payer_data` without an authorization-kind byte, and the `sender` is
recovered from its signature.

## Motivation

In EIP-1559 transactions, the sender must hold the native asset to pay for gas. Insufficient funds
for gas prevent an otherwise valid transaction from being included, even when another party is
willing to fund execution.

An application operating AI agents may want to pay their transaction fees without maintaining a
separate gas balance for each agent account. Sponsorship should let a payer authorize that
expenditure while preserving the sender's execution identity and responsibility for transferred
value. Clients need a common transaction format, authorization procedure, and fee state transition.
The relationship between sender and payer is outside the scope of this EIP.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119
and RFC 8174.

Clients MAY choose their validation and execution scheduling, including parallel execution, provided
that they produce the validity decisions, state transitions, and receipts required by this
specification.

### Parameters

| Parameter | Value | Description |
| --- | --- | --- |
| `TX_TYPE` | `0x53` | The sponsored transaction type byte (EIP-2718). |
| `PAYER_AUTHORIZATION_MAGIC` | `0x00` | Domain-separation byte appended to `TX_TYPE` for an EOA payer digest. |

### Transaction payload

A sponsored transaction is the EIP-2718 envelope `TX_TYPE ‖ TransactionPayload`, where
`TransactionPayload` is the RLP serialization of the following 14-field list. The layout is the
EIP-1559 (`0x02`) field list, extended with `payer` and `payer_data` immediately before the `sender`
signature. The payload MUST contain exactly 14 fields:

```text
TX_TYPE ‖ rlp([
  chain_id,                  # uint64
  nonce,                     # uint64
  max_priority_fee_per_gas,   # uint64
  max_fee_per_gas,            # uint64
  gas_limit,                 # uint64
  to,                        # 20-byte address, or empty for contract creation
  value,                     # uint256
  data,                      # bytes
  access_list,               # [[address, [storage_key, ...]], ...]
  payer,                     # 20-byte non-zero address
  payer_data,                # bytes: payer authorization data
  y_parity,                  # 0 | 1: sender signature
  r,                         # uint256: sender signature
  s                          # uint256: sender signature
])
```

Field semantics (those not listed are as in EIP-1559):

- `chain_id`, `nonce`, `max_priority_fee_per_gas`, `max_fee_per_gas`, and `gas_limit` MUST fit
  unsigned 64-bit integers. `value` is an unsigned 256-bit integer. The fields retain their
  corresponding RLP scalar encodings; `to`, `data`, and `access_list` use the existing
  typed-transaction layouts.

- `payer` identifies the account whose `SponsorRegistry` locked balance funds an accepted sponsored
  transaction. It MUST be exactly 20 bytes and MUST NOT be the zero address. It MAY equal `sender`.

- Payer authorization is selected by the `payer` account code: empty code uses ECDSA; non-empty code
  uses the contract-authorization path.

- `payer_data` contains the payer authorization data. For an empty-code payer it is a 65-byte ECDSA
  signature encoded as `r ‖ s ‖ y_parity`, where `r` and `s` are 32-byte big-endian integers and
  `y_parity` is one byte (`0x00` or `0x01`). For a non-empty-code payer it is contract-specific
  authorization data passed as `PaymentContext.payerData`.

- The payload contains no `payer_auth_kind` or `sender_auth_kind` field.

- `(y_parity, r, s)` is the `sender`'s ECDSA signature. The recovered `sender` is the transaction
  origin and the caller of the initial EVM message. Naming a `payer` does not substitute the `payer`
  for that caller.

The `sender` is not a separate payload field. It is recovered from `(y_parity, r, s)`, as in
existing signed typed transactions.

### Sender authorization

The sender signs the digest

```text
sender_digest = keccak256(TX_TYPE ‖ rlp([
  chain_id, nonce,
  max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
  to, value, data, access_list,
  payer, payer_data
]))
```

The `sender` is the address recovered from `(y_parity, r, s)` over `sender_digest`. The preimage
includes `payer` and `payer_data`, so the `sender` signature commits to the chosen `payer` and the
supplied authorization data.

Both the `sender` signature `(y_parity, r, s)` and an EOA `payer` signature in `payer_data` MUST
satisfy the same ECDSA validity constraints as an EIP-1559 transaction signature: `y_parity` is 0 or
1, `r` and `s` are non-zero and less than the secp256k1 curve order `n`, and `s` is in the lower
half of the range (`s <= n/2`, the EIP-2 low-`s` requirement). A signature failing any of these is
invalid; clients MUST NOT accept a signature merely because it recovers to an address.

### Payer authorization

For a `payer` with empty account code, `payer_data` is a 65-byte string encoding an ECDSA signature
by `payer`, laid out as

```text
payer_data = r ‖ s ‖ y_parity        # 32 + 32 + 1 = 65 bytes
```

where `r` and `s` are 32-byte big-endian integers and `y_parity` is a single byte equal to `0x00` or
`0x01`. The signature is over

```text
payer_digest = keccak256(TX_TYPE ‖ PAYER_AUTHORIZATION_MAGIC ‖ rlp([
  chain_id, sender, nonce,
  max_priority_fee_per_gas, max_fee_per_gas, gas_limit
]))
```

`sender` is the address recovered from the sender signature, and `nonce` is the transaction nonce of
that sender. The remaining fields are taken directly from the transaction. The payer signature MUST
satisfy the ECDSA constraints above and recover to `payer`.

The payer authorization binds `chain_id`, `sender`, `nonce`, the fee parameters, and `gas_limit`. It
does not bind `to`, `value`, `data`, or `access_list`. The sender signature covers all unsigned
transaction fields, including the call, `payer`, and `payer_data`.

The EOA `payer` signature is carried as one 65-byte string in `payer_data`. The `sender` signature
occupies the top-level RLP integer fields `y_parity`, `r`, and `s`. Clients MUST decode these two
representations separately.

The `sender` preimage starts with `TX_TYPE` followed by an RLP list. The EOA `payer` preimage starts
with `TX_TYPE` followed by `PAYER_AUTHORIZATION_MAGIC` (`0x00`) and an RLP list. This extra
`payer`-domain byte separates the two signing preimages.

### Transaction validity

A sponsored transaction MUST satisfy the transaction encoding, sender authorization, nonce, fee,
intrinsic-gas, funding, and payer-authorization requirements specified in this EIP. These checks
MUST use the state and block context prescribed for each check. Admission-time checks do not replace
validation against that context.

A transaction that fails a funding check or payer authorization is invalid and MUST NOT be included
in a valid block. Validation of an invalid transaction MUST NOT commit state changes, logs, refunds,
nonce increments, or fee charges.

A transaction body that reverts or exhausts its available gas after successful validation produces
an execution failure. The payer remains responsible for the applicable transaction gas charges.

1. `TX_TYPE` is recognized and the payload RLP-decodes to exactly the field list above, with each
   field well-typed.

2. `payer` MUST be a non-zero 20-byte address. There are no authorization-kind fields; a payload
   with extra fields fails the exact field-count check.

3. The sender signature `(y_parity, r, s)` over `sender_digest` recovers to an address `sender`
   whose account nonce equals the transaction nonce. The sender account MUST have empty code or
   delegation code.

4. For an empty-code payer, `payer_data` MUST be exactly 65 bytes and satisfy "Payer authorization".
   For a non-empty-code payer, authorization MUST satisfy "Contract payer authorization". Both
   authorization paths are subject to the funding conditions below.

5. `max_fee_per_gas` MUST be at least `max_priority_fee_per_gas` and the block base fee. Both fee
   fields MUST fit unsigned 64-bit integers. `gas_limit` MUST cover the intrinsic gas specified
   under "Gas accounting".

6. Funding eligibility is determined by the payer's vault in `SponsorRegistry`. The same funding
   checks apply to EOA and contract payers. No separate payer allowlist or registration flag is
   required. Passing the funding checks does not establish payer authorization.

   Let `M` and `G` be the maximum transaction count per block and maximum gas limit per transaction
   supplied by the chain configuration for the block, and let `P` be the vault's `max_gasprice`. The
   water level is `W = min(M * G * P, 2^256 - 1)`, computed without intermediate overflow. A zero
   `M` or `G` makes the transaction invalid. The vault MUST have `withdraw_pending_amount = 0` and
   `lock_balance >= W`.

   Admission reads the latest committed vault state and requires `max_fee_per_gas <= P`. Validation
   for block `N` reads the vault at block `N - 1` and requires `effective_gas_price <= P`. A top-up
   or `max_gasprice` increase in block `N` therefore takes effect for sponsorship from block
   `N + 1`.

   Admission also requires the sender's ordinary balance to cover `value`. When `payer` equals
   `sender`, the vault and ordinary balance remain separate funding sources; passing a funding check
   does not reserve funds for an individual transaction.

### Gas accounting (state transition)

For a valid sponsored transaction, gas fees are recorded against `payer` and settled from its
`SponsorRegistry` locked balance at block level; `value` is transferred from `sender`. Neither
ordinary account balance is pre-debited by `gas_limit * max_fee_per_gas`. An invalid transaction
commits no fee charge or nonce increment.

Let `base_fee_per_gas` be the block's base fee and

```text
priority_fee_per_gas = min(max_priority_fee_per_gas, max_fee_per_gas - base_fee_per_gas)
effective_gas_price  = base_fee_per_gas + priority_fee_per_gas
```

The following state transition applies only to transactions that satisfy all validity requirements.
Funding or payer-authorization failure makes the transaction invalid; validation MUST NOT commit
state changes, logs, refunds, nonce increments, or fee charges.

1. **Funding check.** Evaluate the `SponsorRegistry` funding conditions described under "Transaction
   validity", using the prescribed block context and effective gas price. The sender supplies
   `value` from its ordinary account balance. There is no combined
   `gas_limit * max_fee_per_gas + value` check when `payer` equals `sender`.

2. **Payer authorization.** After the funding check, evaluate payer authorization. If authorization
   fails, the transaction is invalid and the body MUST NOT execute. Revert the authorization frame's
   state changes and discard its logs and refund counter. The invalid transaction produces no
   canonical receipt, fee charge, or nonce increment.

3. **Nonce.** On the accepted path, the `sender` `nonce` is incremented once under the normal call
   or creation rules. There is no separate `payer` `nonce` increment for sponsoring the transaction.

4. **Execution.** Execute the body with `sender` as the caller of the initial EVM message. Transfer
   `value` from `sender` under the normal call or creation rules. Intrinsic gas includes
   `payer_data` at the calldata byte rates. Contract-`payer` authorization also consumes gas from
   this transaction. Let `gas_used` be the final gas usage after the applicable refund rules.

5. **Fee obligation.** Record `gas_used * effective_gas_price` as the `payer`'s fee obligation.
   Unused gas and allowed refunds reduce this amount. Since gas was not prepaid from an ordinary
   account balance, no corresponding gas refund is credited to `sender` or `payer`.

6. **Settlement and fee split.** For each `payer` in block `N`, let `owed` be the sum of its
   recorded fee obligations, `L_prev` its locked balance at block `N - 1`, and `L_final` the locked
   balance after the block's transaction writes but before settlement. If the block has no write to
   that slot, `L_final = L_prev`.

   Debit `charged = min(owed, L_prev, L_final)` and store `L_final - charged` before sealing block
   `N`. Funds locked in block `N` do not increase `L_prev`.

   If `charged < owed`, keep the partial debit; the shortfall does not reject or roll back the block
   and is not retried or `charged` to the `sender`. Settlement does not revise transaction receipts
   or priority fees.

   The priority component is `gas_used * priority_fee_per_gas`; the base-fee component is excluded
   from the block-author tip.

If the transaction body reverts after sponsorship is accepted, the payer still owes
`gas_used * effective_gas_price`, the sender nonce increment persists, and the body's value transfer
is reverted. For a contract payer, accepted authorization effects are outside the body's rollback
boundary.

`sender` and `payer` MAY be the same account. Gas is still funded through that account's
`SponsorRegistry` vault, while `value` comes from its ordinary balance. Self-payment does not switch
the transaction to the EIP-1559 prepayment and refund path.

### Receipt

The receipt for a sponsored transaction is encoded identically to an EIP-1559 (`0x02`) receipt,
under the `TX_TYPE` receipt envelope of EIP-2718: the receipt payload is
`rlp([status, cumulative_gas_used, logs_bloom, logs])`, with no sponsorship-specific fields. This
EIP adds no fields to the receipt and does not change the receipts root computation beyond the type
byte of the envelope. The `payer` is not stored in the receipt; a consumer that needs it reads it
from the transaction body (the `payer` field), which is available wherever the transaction itself
is.

### Contract payer authorization

Payer authorization is selected by the payer account code. Empty-code payers use the ECDSA
authorization specified under "Payer authorization". Non-empty-code payers, including accounts
carrying delegation code, use contract authorization.

Before invoking a contract payer, the client MUST verify the `SponsorRegistry` funding conditions
specified under "Transaction validity". If a funding check fails, the client MUST NOT invoke the
authorization call.

```solidity
struct Call {
    address to;
    uint256 value;
    bytes data;
}

struct PaymentContext {
    uint256 chainId;
    address sender;
    uint64 nonce;
    uint64 gasLimit;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    Call[] calls;
    bytes payerData;
}

interface IERC165 {
    function supportsInterface(bytes4 interfaceId)
        external
        view
        returns (bool);
}

interface ISponsor {
    function willPay(PaymentContext calldata ctx)
        external
        returns (bool willing);
}
```

#### Registry interface validation

Before accepting a deposit or top-up through `lock()` or `lockFor(payer)`, `SponsorRegistry` MUST
check the payer's account code. For `lock()`, the payer is `msg.sender`; for `lockFor(payer)`, it is
the specified payer. Empty-code payers are exempt from interface detection. For a non-empty-code
payer, the Registry MUST probe the payer address, including when that address is a proxy or carries
delegation code, using [ERC-165](https://eips.ethereum.org/EIPS/eip-165).

Each probe MUST be a `STATICCALL` from `SponsorRegistry` to the payer, with a gas limit of `30,000`
and ABI-encoded `supportsInterface(bytes4)` calldata. The probes MUST run in the following order,
stopping on failure:

1. `supportsInterface(0x01ffc9a7)` returns `true`.

2. `supportsInterface(0xffffffff)` returns `false`.

3. `supportsInterface(0x1e0cf379)` returns `true`.

Each probe MUST succeed and return exactly one 32-byte canonical ABI boolean with the expected
value. A reverted call, an out-of-gas failure, a malformed return, or an unexpected value MUST
revert the deposit call. `ISponsor` contains only `willPay`, so its interface ID is `0x1e0cf379`;
`IERC165` is checked separately.

These checks apply to deposits and top-ups only. Withdrawals and claims MUST NOT depend on interface
support. Probe gas is charged to the enclosing deposit transaction. Clients MUST NOT add ERC-165
probes to the sponsored-transaction authorization procedure. Contract payers remain subject to the
funding checks and `willPay` authorization specified here.

#### Transaction authorization

The client MUST construct the calldata for `willPay(PaymentContext)`, whose function selector is
`0x1e0cf379`. The call is non-static, uses `sender` as its caller, transfers zero value, and starts
at call depth 1.

The client MUST derive the context fields from the transaction. `sender` is the recovered sender
address. `calls` MUST contain exactly one element containing the transaction's destination, value,
and data; the destination is the zero address for contract creation. `payerData` MUST contain
`payer_data` unchanged. This field is interpreted by the payer contract and MAY be empty.

Let `G` be the block's configured maximum gas limit per transaction. The authorization cap is
`min(G, 20,000,000)`, or `20,000,000` if `G` is zero. The zero-`G` funding rejection rule still
applies. The call receives `min(cap, gas remaining after intrinsic gas)`. A non-positive allowance
causes authorization failure.

Gas consumed by the authorization call is deducted from the transaction's remaining gas.
Authorization succeeds only if the call succeeds, returns the canonical ABI encoding of `true`
(exactly 32 bytes: 31 zero bytes followed by `0x01`), and executes no `SELFDESTRUCT` in the
authorization frame or its descendants, including a descendant that later reverts.

On authorization failure, the authorization frame's state changes MUST be rolled back, and its logs
and refund counter MUST be discarded. Accepted authorization preserves its writes and logs even if
the transaction body later fails. Its logs precede the body logs, and its refund counter is combined
with the body's under a single transaction refund cap.

Sender authorization uses ECDSA. The payload contains neither `sender_auth_kind` nor an explicit
`sender` field.

## Test Cases

The following cases test the transaction encoding, authorization rules, and state transition
specified above:

1. **Round-trip encoding.** Encode and decode the 14-field sponsored transaction, checking field
   order and types, including `payer` and `payer_data`.

2. **Sender signature.** `sender_digest` is computed over the listed field set; recovery of
   `(y_parity, r, s)` yields the expected `sender`, and that `sender`'s `nonce` is checked.

3. **Payer authorization.** For an empty-code payer, `payer_data` is exactly 65 bytes in
   `r ‖ s ‖ y_parity` form and recovers to `payer`. Changing `chain_id`, `sender`, `nonce`, either
   fee field, or `gas_limit` changes `payer_digest`. Changing only `to`, `value`, `data`, or
   `access_list` leaves `payer_digest` unchanged but changes `sender_digest`. Each alternative
   requires a new sender signature. A `payer_data` length other than 65 fails EOA authorization.

4. **Domain separation.** A signature valid as `sender_digest` does not validate as `payer_digest`,
   and vice versa.

5. **Gas accounting.** For a valid transaction, record `gas_used * effective_gas_price` for `payer`
   and settle the aggregate from its vault. Check `payer_data` intrinsic gas, the priority-fee
   component, and the absence of an ordinary-account gas prepayment or refund. A body revert retains
   the payer obligation and sender nonce but reverts the body's value transfer. Funding or
   authorization failure makes the transaction invalid and commits no transaction effects. For
   settlement, `(L_prev, L_final, owed) = (1000, 0, 300)` yields `charged = 0` and a final locked
   balance of `0`; `(500, 500, 500)` yields `charged = 500` and a final locked balance of `0`.

6. **Funding and contract authorization.** Check the vault water level, pending withdrawal, and
   `max_gasprice` conditions, and the sender's `value` balance at normal admission. When `payer`
   equals `sender`, apply the same separate vault and ordinary-balance checks. Failed funding checks
   prevent the authorization call. Verify the fixed function selector, the transaction-derived
   context, empty `payer_data`, the canonical ABI encoding of `true`, and the specified failure and
   rollback conditions.

7. **Registry interface detection.** Verify all three probes for initial deposits and top-ups,
   including `lockFor` by another account. Check the payer target, Registry caller, per-call gas
   limit, and canonical return values. A failed or malformed probe reverts the deposit. Empty-code
   payers skip detection. Withdrawals and claims remain independent of interface support.
   Contract-payer transaction authorization performs the specified funding checks and `willPay` call
   without an additional ERC-165 probe.

8. **Payload shape.** Reject RLP lists with fewer or more than 14 fields.

9. **Field constraints.** Reject a zero or incorrectly sized `payer`. Enforce the fee inequalities
   and the unsigned 64-bit bounds for `chain_id`, `nonce`, `gas_limit`, and both fee fields.

The following vector tests encoding and EOA signature recovery; it does not assert successful
execution. Decoding and re-encoding produce the same signed transaction, and signature recovery
yields the `sender` and `payer` shown.

```text
chain_id = 1337
nonce = 0
max_priority_fee_per_gas = 1
max_fee_per_gas = 10
gas_limit = 50000
to = 0x (contract creation)
value = 0
data = 0x6000
access_list = []
sender = 0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a
payer = 0x1563915e194d8cfba1943570603f7606a3115508
payer_digest = 0xa869aff4d1e5e7842591555af8f4d4ae957f4f16ce67846dae43ce4917401143
payer_data = 0x8db884349cab407ff72e20e2210dce9c197fb20972669e5229c63b6797a9786813be0756a50d40116344bea784813e3edc06c12297b69c28bb517609c3da324f00
sender_digest = 0xbcdd6a47eb61aebd0bf0c10495715e0b79117e7574f9c29232a13c1dd469e761
signed_transaction = 0x53f8aa82053980010a82c3508080826000c0941563915e194d8cfba1943570603f7606a3115508b8418db884349cab407ff72e20e2210dce9c197fb20972669e5229c63b6797a9786813be0756a50d40116344bea784813e3edc06c12297b69c28bb517609c3da324f0001a095792930f25103b264d0214d94b1474761e60ac682fcf4fb872025f7fc0464d0a04ada0eb20f64b5be56c19f9c34fcf026079129a9393da5d5171ab398a1d441eb
transaction_hash = 0xc66e09ea428485b2dbf61a7c74b39acaf302aa8670b3dd7d4f212c06709607fe
```

## Rationale

### Protocol scope

Transaction encoding, authorization, and gas accounting determine whether a sponsored transaction is
valid and how it changes state. Sponsored fees accrue during execution and are settled from
`SponsorRegistry` balances at block level, so settlement is part of the state transition. Local
queue policy remains outside the scope of this EIP. Clients may choose their internal execution
scheduling while preserving the validity decisions, state transitions, and receipts specified here.

### Payer pays gas, sender pays value

Separating gas funding from `value` transfer allows a `payer` to fund execution while the `sender`
remains responsible for transferred `value`. Block-level vault settlement avoids writing the same
`payer` balance after every transaction, which would create a shared dependency between otherwise
independent transactions. The previous-block funding snapshot gives those transactions a common
funding check; its cost is that a top-up cannot fund sponsorship in the same block. A contract
`payer` that updates shared quota state can still introduce execution dependencies.

### ECDSA sender and account-based payer authorization

ECDSA recovery identifies the `sender` without an explicit sender field. Selecting payer
authorization by account code lets `payer_data` carry either a signature or contract-specific
authorization data passed as `PaymentContext.payerData`, without a kind discriminator. Allowing the
authorization call to write state lets a payer update quotas or per-sender accounting together with
its acceptance decision. Authorization failure rolls those changes back; acceptance retains them
even if the transaction body fails, so the payer can account for failed attempts it agreed to fund.

### Payer identity and signing domains

`sender_digest` commits to `payer` and `payer_data`, fixing the selected payer and authorization
data. Payer identity comes from signature recovery, so the EOA payer digest need not repeat `payer`.
The additional `0x00` byte separates the payer signing domain.

An EOA payer authorizes gas expenditure for a specified sender nonce and set of fee parameters. The
sender chooses the destination, transferred value, calldata, and access list, and authorizes those
choices with its own signature. This allows the sender to change the call without obtaining another
payer signature, provided that the payer-bound fields remain unchanged.

Sponsorship introduces no separate payer nonce. Transactions from different senders do not share a
payer nonce sequence. Transactions from the same sender remain subject to that sender's nonce
ordering. Shared execution state may still introduce dependencies between transactions.

If `payer` equals `sender` and the `payer` has empty code, both ECDSA authorizations remain
required: the `sender` signs `TX_TYPE ‖ rlp(...)`, and the `payer` signs
`TX_TYPE ‖ 0x00 ‖ rlp(...)`. Self-payment does not change the payload layout. A non-empty-code
`payer` follows the contract-authorization path even when it is also the `sender`.

### Transaction type

`TX_TYPE` is `0x53`. The type byte identifies the sponsored transaction envelope and forms part of
both signing preimages.

## Backwards Compatibility

- The EIP-2718 envelope ensures `TX_TYPE` does not disrupt legacy transactions (`>= 0xc0`) or
  existing typed transactions.

- Tooling that does not support `TX_TYPE` needs the 14-field encoding and the signing preimages
  specified above. Existing ECDSA engines can produce the sender signature and an empty-code payer
  signature. A non-empty-code payer uses contract-specific authorization data passed as
  `PaymentContext.payerData` instead of a second ECDSA signature. New deposits and top-ups for
  non-empty-code payers must pass the Registry's ERC-165 checks.

- A transaction where `payer` equals `sender` still uses sponsored-transaction authorization,
  `payer_data` gas charging, and `SponsorRegistry` settlement. It does not become an ordinary
  EIP-1559 transaction.

## Security Considerations

- **Authorization replay.** A payer authorization may be reused with different destinations, values,
  calldata, or access lists while its signed fields remain unchanged. Each alternative requires a
  sender signature over its complete payload. Once a transaction consumes the sender nonce, another
  transaction using that nonce cannot be executed on the same canonical history.

- There is no independent payer nonce, expiry, or per-authorization revocation field. A pending
  withdrawal or insufficient vault funding can prevent sponsorship without invalidating the
  signature itself; restoring eligibility can make it usable again. Funding checks do not reserve
  funds for outstanding authorizations, and actual gas consumption depends on execution state and
  the access list.

- **Fixed signing domains.** The `sender` preimage is `TX_TYPE ‖ rlp(...)`; the EOA `payer` preimage
  is `TX_TYPE ‖ 0x00 ‖ rlp(...)`. Changing either prefix or the listed fields changes signature
  validation.

- **Payer fee exposure.** The signed gas and fee fields bound an EOA payer's gas expenditure for the
  transaction. Contract payers authorize gas expenditure through `willPay`. Funding or
  payer-authorization failure makes the transaction invalid and commits no fee charge. A subsequent
  failure of the transaction body does not invalidate an otherwise valid transaction whose payer
  authorization has succeeded; the payer remains responsible for the applicable gas charges.

- **Blind signing.** Wallets presenting a payer authorization should identify the sender, nonce, gas
  limit, and fee parameters, and make the authorization scope explicit. An EOA payer authorization
  does not enforce restrictions on the transaction's destination or call contents. Wallets
  presenting the sender signature should also show the designated payer, destination, value,
  calldata, and access list.

- **Authorization interpretation.** The payer account code determines whether `payer_data` is an
  ECDSA signature or contract-specific authorization data passed as `PaymentContext.payerData`.
  Authorization-kind fields are absent from the 14-field payload. Accepting additional fields would
  alter transaction decoding and signature validation.

- **Interface declarations.** ERC-165 reports declared interface support. A successful check does
  not establish correct contract behavior or consent to pay. Later code deployment, upgrades, or
  delegation changes can alter interface support. Each sponsored transaction naming a non-empty-code
  payer still requires successful `willPay` authorization.

- **Validation resources.** Invalid transactions can consume validation resources even though they
  cannot be included in a valid block. Nodes may apply local admission, caching, and rate-limiting
  policies to limit repeated unsuccessful validation. Such policies do not change consensus
  validity.
