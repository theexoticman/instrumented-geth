// Copyright 2024 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	ethapi "github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/holiman/uint256"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupSimulatedEthereum(t *testing.T) (*simulated.Backend, *eth.Ethereum, *ecdsa.PrivateKey, common.Address) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	genesisAlloc := map[common.Address]types.Account{
		addr: {Balance: big.NewInt(1e18)},
	}

	backend, ethService, err := simulated.NewSimulatedEthereumBackend(genesisAlloc)
	require.NoError(t, err)
	require.True(t, ethService.IsSimulateMode())

	return backend, ethService, key, addr
}

// TestSimulateSimpleTransfer verifies that a basic ETH transfer transaction
// is successfully executed and mined in the simulated backend environment.
// TestSimulateSimpleTransfer performs a basic simulated transaction and asserts state
// TestSimulateSimpleTransfer performs a basic simulated transaction and asserts state
func TestSimulateSimpleTransfer(t *testing.T) {
	backend, ethService, senderKey, senderAddr := setupSimulatedEthereum(t)
	defer backend.Close()

	ctx := context.Background()
	client := ethclient.NewClient(backend.Node().Attach())

	recipientKey, _ := crypto.GenerateKey()
	recipientAddr := crypto.PubkeyToAddress(recipientKey.PublicKey)

	nonce, err := client.PendingNonceAt(ctx, senderAddr)
	assert.NoError(t, err)

	gasPrice, err := client.SuggestGasPrice(ctx)
	assert.NoError(t, err)

	amount := big.NewInt(1e17)
	tx := types.NewTransaction(nonce, recipientAddr, amount, 21000, gasPrice, nil)
	signer := types.LatestSignerForChainID(big.NewInt(1337))
	signedTx, err := types.SignTx(tx, signer, senderKey)
	assert.NoError(t, err)

	// RLP encode the transaction for SendRawTransaction
	rlpTx, err := signedTx.MarshalBinary()
	assert.NoError(t, err)

	// Get the TransactionAPI
	// Pass the ethService itself, as it implements the ethapi.Backend interface
	// and also provides the IsSimulateMode/SimChainStore methods needed by the simulation check.
	txAPI := ethapi.NewTransactionAPI(ethService.APIBackend, new(ethapi.AddrLocker))

	// Call SendRawTransaction, which uses simulateAndStore internally in simulate mode
	txHash, err := txAPI.SendRawTransaction(ctx, rlpTx)

	assert.NoError(t, err)
	assert.Equal(t, signedTx.Hash(), txHash, "SendRawTransaction should return the correct hash")

	// Assertions checking the simStore remain the same
	simStore := ethService.SimChainStore()
	require.NotNil(t, simStore, "SimChainStore should not be nil")

	txFromStore, _ := simStore.GetTransaction(signedTx.Hash())
	assert.NotNil(t, txFromStore, "transaction should be stored in SimChainStore")

	receiptFromStore, _ := simStore.GetReceipt(signedTx.Hash())
	assert.NotNil(t, receiptFromStore, "receipt should be stored in SimChainStore")

	// blockFromStore, _ := simStore.GetBlockByHash(receiptFromStore.BlockHash)
	// assert.NotNil(t, blockFromStore, "block should be stored in SimChainStore")

	uAmount, _ := uint256.FromBig(big.NewInt(0))
	accountState := simStore.GetAccount(senderAddr)
	assert.NotNil(t, accountState, "sender account state should be bigger than 0")
	assert.True(t, accountState.Balance.Cmp(uAmount) > 0, "balance should be reduced")

	accountStateRecipient := simStore.GetAccount(recipientAddr)
	assert.NotNil(t, accountStateRecipient, "recipient account state should be stored in SimChainStore")

	zAmount, _ := uint256.FromBig(big.NewInt(0))
	assert.True(t, accountStateRecipient.Balance.Cmp(zAmount) > 0, "recipient should have received funds")

}

// TestEventTracer test if the event tracer works and collect the logs and generate the new custom structure correctly

func TestEventTracer(t *testing.T) {
	backend, ethService, senderKey, senderAddr := setupSimulatedEthereum(t)
	defer backend.Close()

	ctx := context.Background()
	client := ethclient.NewClient(backend.Node().Attach())

	recipient1Key, _ := crypto.GenerateKey()
	recipient1Addr := crypto.PubkeyToAddress(recipient1Key.PublicKey)

	recipient2Key, _ := crypto.GenerateKey()
	recipient2Addr := crypto.PubkeyToAddress(recipient2Key.PublicKey)

	nonce, err := client.PendingNonceAt(ctx, senderAddr)
	assert.NoError(t, err)

	gasPrice, err := client.SuggestGasPrice(ctx)
	assert.NoError(t, err)

	amount := big.NewInt(1e17)
	tx1 := types.NewTransaction(nonce, recipient1Addr, amount, 21000, gasPrice, nil)
	tx2 := types.NewTransaction(nonce, recipient2Addr, amount, 21000, gasPrice, nil)
	signer := types.LatestSignerForChainID(big.NewInt(1337))
	signedTx1, err := types.SignTx(tx1, signer, senderKey)
	assert.NoError(t, err)
	signedTx2, err := types.SignTx(tx2, signer, senderKey)

	assert.NoError(t, err)

	// RLP encode the transaction for SendRawTransaction
	rlpTx1, err := signedTx1.MarshalBinary()
	assert.NoError(t, err)
	rlpTx2, err := signedTx2.MarshalBinary()
	assert.NoError(t, err)

	// Get the TransactionAPI
	// Pass the ethService itself, as it implements the ethapi.Backend interface
	// and also provides the IsSimulateMode/SimChainStore methods needed by the simulation check.
	txAPI := ethapi.NewTransactionAPI(ethService.APIBackend, new(ethapi.AddrLocker))

	// Call SendRawTransaction, which uses simulateAndStore internally in simulate mode
	txHash1, err := txAPI.SendRawTransaction(ctx, rlpTx1)
	if err != nil {
		fmt.Println("error", err)
	}
	txHash2, err := txAPI.SendRawTransaction(ctx, rlpTx2)
	if err != nil {
		fmt.Println("error", err)
	}

	fmt.Println("txHash1", txHash1)
	fmt.Println("txHash2", txHash2)
	os.Stdout.Sync()
	//Get the events txHash1
	events, _ := ethService.SimChainStore().GetTxEvents(txHash1)
	assert.Equal(t, 4, len(events.EventsByContract), "events should be stored in SimChainStore")

	//Get the events txHash2
	events, _ = ethService.SimChainStore().GetTxEvents(txHash2)
	assert.Equal(t, 4, len(events.EventsByContract), "events should be stored in SimChainStore")

	//Get the events txHash1
}
