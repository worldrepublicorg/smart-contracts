# World Republic Smart Contracts Repository

This repository serves as a reference for the World Republic smart contracts. It contains:

- **Smart Contract Files:**

  - `Staking20Base.sol` (modified from thirdweb's [Staking20Base](https://github.com/thirdweb-dev/contracts/blob/389f9456571fe554d7a048d34806cbbe7b3ec909/contracts/base/Staking20Base.sol))
  - `Staking20.sol` (modified from thirdweb's [Staking20](https://github.com/thirdweb-dev/contracts/blob/389f9456571fe554d7a048d34806cbbe7b3ec909/contracts/extension/Staking20.sol#L4) implementation, used by Staking20Base)
  - `OpenLetter.sol`

- **Deployment Addresses:**
  - `Staking20Base.sol`: `0x2f08c17b30e6622f8b780fb58835fc0927e2dc8e`
  - `TokenERC20.sol` (Drachma): `0xAAC7d5E9011Fc0fC80bF707DDcC3D56DdfDa9084`
  - `OpenLetter.sol`: `0x80C090D6Fe14c45329B730c9aE86E37a1A335F5c` (only the first deployment address is listed, as this contract will be deployed multiple times)

**Key Features:**

- The `Staking20Base.sol` contract provides the basic income distribution mechanism for the World Republic
- The `Staking20.sol` contract contains the core staking logic that has been modified to suit the World Republic's needs
- The `OpenLetter` contract allows users to create and sign open letters, with the ability to remove signatures.
- Drachma (WDD) is the official currency and payment token of the World Republic, deployed as a [thirdweb TokenERC20](https://thirdweb.com/thirdweb.eth/TokenERC20)

**Important:**  
This repository is provided for documentation purposes only. Do **not** clone this repo for deploying or testing the contracts.
