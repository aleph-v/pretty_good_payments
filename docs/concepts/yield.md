# Yield Distribution

PGP enables free transactions for users by paying sequencers through yield generated on deposited funds. Instead of charging transaction fees, the system routes deposits through yield-generating vaults (like Aave or Compound) and distributes the earnings to sequencers based on their contribution to block production.

## The Economic Model

Traditional L2s charge users transaction fees that go to sequencers. PGP inverts this model: users deposit funds that generate yield, and that yield pays sequencers. Users get free transactions; sequencers get paid from yield rather than fees.

This creates interesting incentive alignment:
- Users benefit from free transactions and still earn yield on funds they're not actively using
- Sequencers are motivated to process transactions (more data = more yield share)
- The system scales with TVL - more deposits mean more yield to distribute

## Yield Generation

When users deposit tokens into PGP, the tokens don't sit idle. The YieldRouter immediately deposits them into an ERC4626-compliant vault. These vaults wrap yield-generating protocols:

- Aave's aTokens
- Compound's cTokens
- Yearn vaults
- Any protocol with an ERC4626 wrapper

The YieldRouter tracks the "principal" separately from the vault's current value. Principal is the total amount deposited minus withdrawals. The difference between current value and principal is yield.

## Period-Based Accounting

Rather than calculating yield continuously, the system uses discrete periods. Each period (configurable per network, e.g., one day), the YieldRouter records a snapshot:

1. Check the current value of all vault positions
2. Compare to tracked principal to compute yield
3. Record this yield amount for the period
4. Add the yield to principal (so next period starts fresh)

Anyone can trigger this snapshot by calling `poke()`. The sequencer software typically calls this automatically, but anyone can do it if needed.

### Max Interest Cap

To prevent gaming through deposit timing, the contract owner can set a maximum yield per period for each token. If actual yield exceeds this cap, only the capped amount is recorded - the excess stays in the vault and gets captured in a future period.

This smoothing mechanism makes yield more predictable and smooths out any spikey return yield sources.

## Distribution to Sequencers

Yield is distributed to sequencers based on their contribution to block production, measured through "blob usage."

### Blob Usage Calculation

Each block submission uses some amount of blob space:
- Deposits: 4 fields per 3 deposits (1.33 fields each)
- Transactions: 15 fields each

When a sequencer submits a block, the contract calculates their blob usage and records it. Priority sequencers submitting during their closed period receive a 2x multiplier, incentivizing them to actively use their guaranteed windows.

### Epoch-to-Period Mapping

The system has two time scales:
- **Epochs**: Short periods for sequencer rotation (e.g., 30 minutes)
- **Periods**: Longer periods for yield accounting (e.g., 1 day)

Multiple epochs fit within each period. When a sequencer claims yield for an epoch, the contract:

1. Looks up which period the epoch belongs to
2. Divides the period's total yield by the number of epochs per period
3. Calculates the sequencer's share based on their blob usage percentage in that epoch
4. Sends them that amount from the vault

### Share Calculation

A sequencer's share for an epoch equals:

```
sequencer_yield = (period_yield / epochs_per_period) × (sequencer_blob_use / total_blob_use)
```

For example, if:
- Period yield: $1,000
- Epochs per period: 48
- Sequencer's blob usage: 3,000 fields
- Total blob usage: 10,000 fields

Then: sequencer_yield = ($1,000 / 48) × (3,000 / 10,000) = $6.25

## Claiming Yield

Sequencers don't receive yield automatically - they must claim it. The claim process:

1. **Epoch finalization**: Wait for the epoch to be past the challenge period. Yield can't be claimed for epochs that might still be rolled back.

2. **Challenge check**: The sequencer must not be challenged. Slashed sequencers lose their yield claims along with their stake.

3. **Single claim**: Each (sequencer, epoch, token) combination can only be claimed once. The contract tracks what's been paid.

4. **Withdrawal**: The contract withdraws the calculated amount from the vault directly to the sequencer's address.

Sequencers can batch claims across multiple epochs for gas efficiency using `withdrawMany()`.

## Handling Vault Losses

Yield vaults can experience losses (hacks, bad debt, etc.). The YieldRouter handles this gracefully:

When processing a withdrawal, if the vault's current value is less than the tracked principal, the system calculates a loss ratio. User withdrawals are reduced proportionally - if the vault has 90% of expected value, users receive 90% of their nominal withdrawal.

This ensures:
- Users share losses fairly rather than first-withdrawers getting full value
- The accounting remains consistent even with losses
- Sequencer yields naturally decrease when there's no yield to distribute

## Yield Source Management

The contract owner can:

**Change vault for a token**: If a better vault becomes available, or the current vault has issues, the owner can migrate all funds to a new vault. This is done atomically - withdraw everything from old vault, deposit everything to new vault.

**Add/remove tracked tokens**: The list of tokens that get yield recorded on `poke()` can be updated. This enables adding support for new tokens or removing deprecated ones.

**Set max interest caps**: Per-token caps can be adjusted based on observed yield rates and gaming concerns.

## Economic Considerations

### For Users

Users deposit funds and receive notes they can spend privately. Their funds generate yield, but they don't receive it directly - it goes to sequencers. In exchange, transactions are free.

This is advantageous when:
- Transaction fees would exceed yield lost (most cases with small/medium amounts)
- Privacy is valued (no fee payments to analyze)
- Funds sit idle anyway (yield goes somewhere useful)

### For Sequencers

Sequencers stake ETH and operate infrastructure. Their revenue comes entirely from yield distribution.

Revenue depends on:
- **TVL**: More deposited value = more yield to distribute
- **Yield rates**: Higher APY on vaults = more absolute yield
- **Market share**: More blob usage relative to other sequencers = larger share
- **Priority status**: 2x multiplier during closed periods

Costs include:
- **Stake**: Capital locked that could earn yield elsewhere
- **Gas**: Block submission costs (execution + blob gas)
- **Infrastructure**: Servers, monitoring, development

The system is designed to be profitable at scale with consistent transaction volume.

### Break-Even Analysis

A sequencer breaks even when yield earned exceeds costs. Rough calculation:

- Per-block cost: ~$5 (at moderate gas prices)
- Per-epoch yield: TVL × APY / 365 / epochs_per_day / num_sequencers
- Break-even: need enough TVL and transaction volume

The exact numbers depend heavily on network conditions, vault yields, and sequencer competition.

## Integration with Sequencing

The yield system and sequencing system are tightly coupled:

- `post()` records blob usage for the submitting sequencer
- Priority multiplier incentivizes closed-period submission
- Slashed sequencers lose yield claims
- Epoch finalization gates yield claiming

This creates alignment: sequencers must actively and honestly participate to earn yield. Passive stake-and-wait doesn't generate returns.
