run debug configuration that start geth locally

attach to the ipc 
``` bash
 ./build/bin/geth attach ipc:./datadir/geth.ipc
```

when running using --dev, accounts[0] has funds.

``` js
// In the Geth JS Console:

// Step 1: Prepare the transaction object
var tx = {
  from: eth.accounts[0], // Sender address
  to: "0xb5281fe71e565fd28dcd2df6e669d3cafeba1000", // Recipient address (replace with actual address)
  value: web3.toWei(1, "ether"), // Amount to send (1 ETH in this case)
  gas: 21000, // Gas limit
  gasPrice: web3.toWei(20, "gwei"), // Gas price
  nonce: eth.getTransactionCount(eth.accounts[0], "pending") // Nonce
};

// Step 2: Sign the transaction
eth.signTransaction(tx, eth.accounts[0], function(err, signedTx) {
  if (err) {
    console.error("Error signing transaction: " + err);
  } else {
    console.log("Transaction signed successfully!");

    // Step 3: Send the raw transaction
    eth.sendRawTransaction(signedTx.raw, function(err, txHash) {
      if (err) {
        console.error("Error sending raw transaction: " + err);
      } else {
        console.log("Raw transaction sent! Hash: " + txHash);

        console.log(`Run: eth.getTransactionEvents("${txHash}", function(e,r){ if(e) console.error(e); else console.log(JSON.stringify(r,null,2)); });`);
      }
    });
  }
});

       
```