# Witness Construction for `build_script_f1_blake3_locked`

## Context
`build_script_f1_blake3_locked` is the locking script that enforces the F1 condition:
1. The Schnorr signature must be valid.
2. The public integer `x` must be greater than `F1_THRESHOLD` (100).
3. A BLAKE3 hash of the **12‑byte message** `x || r` must start with the nibble‑prefix that identifies the flow.

The witness therefore has to leave the stack in a very specific state before the locking script begins to run.

---

## Current Witness Layout

The witness is *two* little helper scripts that run **before** the locking script:

1. **`push_compiled`** – produced by `blake3_push_message_script_with_limb`.
   This script simply pushes the 12 raw bytes that form the message.
   With `limb_len = 4` we end up with three 4‑byte pushes:

   ```text
   limb‑2 (bytes 8‑11)
   limb‑1 (bytes 4‑7)
   limb‑0 (bytes 0‑3)
   ```

2. **`witness_f1`** – handcrafted with `Builder::new()`.
   It pushes
   ```text
   x     – the integer value (as Script number)
   sig   – Schnorr signature (PushBytes)
   ```

Put together we get this byte stream which the VM executes from **left → right**:

```text
┌──────────────────┐┌──────────────────┐┌────────────────────┐
│ push_compiled    ││ witness_f1       ││ locking_script (F1)│
└──────────────────┘└──────────────────┘└────────────────────┘
```

### Stack just before the locking script
After the two witness chunks have executed the stack (top first) looks like:

```text
┌───┐              ▲ top
│sig│              │
├───┤              │
│ x │  (Script num)│  ← will be checked > 100
├───┤              │
│L2 │              │  limb‑2 (msg[8..12])
├───┤              │
│L1 │              │  limb‑1 (msg[4..8])
├───┤              │
│L0 │              │  limb‑0 (msg[0..4])
└───┘              ▼ bottom
```

> **Note** `pubkey` is pushed **inside** the locking script, right before `OP_CHECKSIGVERIFY`, so the signature check consumes `sig` (from witness) and `pubkey` (from script) in the right order.

---

## Step‑by‑Step Execution Flow

| #   | Operation              | Effect on Stack                                                 |
| --- | ---------------------- | --------------------------------------------------------------- |
| 1   | `push pubkey`          | pubkey ▽                                                        |
| 2   | `OP_CHECKSIGVERIFY`    | sig & pubkey are popped, script aborts if invalid               |
| 3   | `OP_DUP`               | dup `x` so we can compare it                                    |
| 4   | `push 100`             | 100 ▽                                                           |
| 5   | `OP_GREATERTHAN`       | compares `x > 100` → bool                                       |
| 6   | `OP_VERIFY`            | aborts if false, pops bool                                      |
| 7   | `OP_DROP`              | drop the **original** `x`, exposing limb‑0 at the top           |
| 8   | BLAKE3 compute script  | reads the three 4‑byte limbs, leaves 64 nibbles (little‑endian) |
| 9   | `OP_DROP × (64 - b/4)` | discards the tail of the digest                                 |
| 10  | prefix‑check script    | pushes expected nibbles, runs `OP_EQUALVERIFY` for each         |
| 11  | `OP_TRUE`              | leaves `1` on stack → script succeeds                           |

If every step passes the final stack is `[1]` and F1 is satisfied.

---

## Weakness in the Current Construction
Nothing enforces that

```text
x  (script number)
==
first 4 bytes of the 12‑byte message
```

An attacker (the Operator) could choose

```text
x′ > 100          – to pass the threshold
x || r (bytes)    – so that BLAKE3 prefix still matches the desired flow
```

This breaks the intended semantics.

---

# Roadmap to Improve the Toy Prototype

1. **Enforce `x` Consistency**
   * Reconstruct the 4‑byte little‑endian `x` from the message limbs and compare it with the numeric `x` already on the stack.
   * Sketch:
     ```text
     <after pushing limbs>
     OP_DUP OP_DUP OP_ADD …   -- fold 4 bytes into one Script number
     OP_NIP                  -- swap/remove to align
     OP_EQUALVERIFY          -- compare against provided x
     ```

2. **Clean Witness Layout**
   * Pass **only** `x` and `r` (as numbers or raw bytes).
   * Build the 12‑byte message **inside** the script (currently impossible todo efficintly without `OP_CAT`)

3. **Support Multiple Signers**
   * Extend witness so that *k‑of‑n* Schnorr signatures are provided.
   * Replace `OP_CHECKSIGVERIFY` with a mini‑threshold‑sig routine (`OP_CHECKSIG`, counting successes).

4. **Generalise to F1…F4**
   * Implement F3/F4 to demonstrate the full protocol flow described in the paper.

By completing the tasks above this toy implementation will align much more closely with the ColliderVM reference protocol described in the paper. 