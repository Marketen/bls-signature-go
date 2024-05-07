# bls-signature-go
This project tests a new web3signer endpoint that lets the user sign arbitrary data with its loaded keys.
The endpoint is `/api/v1/eth2/ext/sign/<pubkey>`. With payload as body request 
```
{
  "type": "PROOF_OF_VALIDATION",
  "platform": "dappnode",
  "timestamp": "1711338489397"
}
```
See https://github.com/Consensys/web3signer/pull/982