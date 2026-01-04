# SteadToken Treasury Drain via Public Operator Function on Arbitrum

## ACT Classification

This incident is classified as an Attacker-Caused Theft (ACT). A single adversary-crafted transaction on Arbitrum drains SteadToken funds from a proxy treasury contract and converts them into WETH/ETH profit for the attacker.

## High-Level Summary

- The attacker contract 0x34c7... takes a flash loan of aeWETH from the Balancer Vault.
- It calls into a router/registry combination (not properly access-controlled) that instructs a SteadToken-holding proxy at 0xf9FF... to transfer its entire SteadToken balance to the attacker contract.
- The stolen SteadToken is swapped through a Uniswap V3 pool against an ArbitrumExtensionV2-based USDT token and then into aeWETH.
- The flash loan is repaid, and the remaining aeWETH is unwrapped to ETH and sent to the attacker EOA 0x5fb0....

## Evidence of Theft

- **Unauthorized asset movement**: The SteadToken treasury proxy 0xf9FF... transfers 135,000,000,000 SteadToken units to the attacker contract without any user deposit or permission from protocol governance.
- **Profit to attacker**: Balance diffs show the attacker EOA gaining approximately 5.9454 ETH equivalent, while the WETH token contract loses the same amount via aeWETH.withdraw.
- **Exploitability**: The router function that triggers the treasury transfer is publicly callable; any EOA could have submitted the same transaction under standard inclusion rules.

Taken together, these facts show a repeatable adversary opportunity to steal funds from the SteadToken treasury, satisfying the ACT definition.
