# ltoken

⚠️ This code has a vulnerability. It's [on purpose](https://cairopractice.com/posts/underhanded-cairo-2-intro/). ⚠️

## About

The contract in this repo is a ERC20 token with additional mint and burn functionality. It is an exploration of linear types when used in for keeping token balances. Note the vulnerability doesn't have anything to do with the fact that the token balance deviation from the ERC20 spec (`u128` vs. `u256`).
