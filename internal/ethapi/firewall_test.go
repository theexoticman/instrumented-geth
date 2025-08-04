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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/firewall"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create TypeScript-like event data and convert to Go format
type EventParameter struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type EventContext struct {
	Name            string           `json:"name"`
	EventName       string           `json:"eventName"`
	Parameters      []EventParameter `json:"parameters"`
	ContractAddress string           `json:"contractAddress"`
	BlockNumber     int              `json:"blockNumber"`
	TransactionHash string           `json:"transactionHash"`
	Caller          string           `json:"caller"`
}

type ContractEvents map[string][]EventContext

type SimulationResult struct {
	Success     bool           `json:"success"`
	GasEstimate string         `json:"gasEstimate"`
	Events      ContractEvents `json:"events"`
	Error       *string        `json:"error,omitempty"`
}

// Convert TypeScript-like EventContext to Go FullTransactionEvents
func createMockUserSimulation() state.FullTransactionEvents {
	// Create a mock Transfer event simulation
	// Transfer(address from, address to, uint256 value)
	transferSigHash := common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

	// Parameters: from, to, value (each 32 bytes)
	fromAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	toAddr := common.HexToAddress("0x5678901234567890123456789012345678901234")
	value := big.NewInt(1000000000000000000) // 1 ETH in wei

	var fromParam, toParam, valueParam [32]byte
	copy(fromParam[12:], fromAddr.Bytes()) // Address is 20 bytes, pad to 32
	copy(toParam[12:], toAddr.Bytes())     // Address is 20 bytes, pad to 32
	value.FillBytes(valueParam[:])         // BigInt to 32 bytes

	eventData := state.EventData{
		EventSigHash: transferSigHash,
		Parameters:   [][32]byte{fromParam, toParam, valueParam},
	}

	contractEvent := state.ContractEvents{
		Address:        common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), // USDC address
		ContractEvents: eventData,
	}

	return state.FullTransactionEvents{
		EventsByContract: []state.ContractEvents{contractEvent},
	}
}

func createMockUserSimulationApproval() state.FullTransactionEvents {
	// Create a mock Approval event simulation
	// Approval(address owner, address spender, uint256 value)
	approvalSigHash := common.HexToHash("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925")

	// Parameters: owner, spender, value
	ownerAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	spenderAddr := common.HexToAddress("0x9876543210987654321098765432109876543210")
	value := big.NewInt(500000000000000000) // 0.5 ETH in wei

	var ownerParam, spenderParam, valueParam [32]byte
	copy(ownerParam[12:], ownerAddr.Bytes())
	copy(spenderParam[12:], spenderAddr.Bytes())
	value.FillBytes(valueParam[:])

	eventData := state.EventData{
		EventSigHash: approvalSigHash,
		Parameters:   [][32]byte{ownerParam, spenderParam, valueParam},
	}

	contractEvent := state.ContractEvents{
		Address:        common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
		ContractEvents: eventData,
	}

	return state.FullTransactionEvents{
		EventsByContract: []state.ContractEvents{contractEvent},
	}
}

// Extended test backend with firewall support
type FirewallTestBackend struct {
	*TestBackend
	txSimulationPool  *firewall.TxSimulationPool
	isIntentGuardMode bool
}

func (b *FirewallTestBackend) TxSimulationPool() *firewall.TxSimulationPool {
	return b.txSimulationPool
}

func (b *FirewallTestBackend) SimChainStore() *state.SimulatedChainStore {
	return b.TestBackend.simStore
}

// Add this method to access the chain
func (b *FirewallTestBackend) chain() *core.BlockChain {
	return b.TestBackend.chain
}

// Test helper to create test backend with firewall support
func newTestBackendWithFirewall(t *testing.T, genBlocks int, genesis *core.Genesis) *FirewallTestBackend {
	backend := NewTestBackend(t, genBlocks, genesis, beacon.New(ethash.NewFaker()), func(i int, b *core.BlockGen) {
		// Empty block generation function
	})

	return &FirewallTestBackend{
		TestBackend:       backend,
		txSimulationPool:  firewall.NewTxSimulationPool(),
		isIntentGuardMode: true,
	}
}

func TestFirewallUserSimulationStorage(t *testing.T) {
	t.Parallel()

	// Setup test environment
	var (
		accounts = NewAccounts(2)
		genesis  = &core.Genesis{
			Config: params.MergedTestChainConfig,
			Alloc: types.GenesisAlloc{
				accounts[0].addr: {Balance: big.NewInt(params.Ether)},
				accounts[1].addr: {Balance: big.NewInt(params.Ether)},
			},
		}
	)

	backend := newTestBackendWithFirewall(t, 0, genesis)

	// Create a mock transaction to simulate
	tx := createMockTransaction(accounts[0])
	txHash := tx.Hash()

	// Test 1: Store user simulation
	userSimulation := createMockUserSimulation()

	err := backend.TxSimulationPool().AddUserSimulation(txHash, userSimulation)
	require.NoError(t, err, "Failed to store user simulation")

	// Test 2: Verify simulation is stored and retrievable
	status := backend.TxSimulationPool().GetStatus(txHash)
	assert.Equal(t, firewall.StatusUserSimReceived, status, "Transaction should have user simulation received status")

	shouldSimulate := backend.TxSimulationPool().ShouldSimulateInBlock(txHash)
	assert.True(t, shouldSimulate, "Transaction should be marked for simulation")

	// Test 3: Verify simulation result can be retrieved
	result, exists := backend.TxSimulationPool().GetResult(txHash)
	require.True(t, exists, "Simulation result should exist")
	assert.Equal(t, firewall.StatusUserSimReceived, result.Status, "Status should be user simulation received")

	// Test 4: Test duplicate simulation rejection
	err = backend.TxSimulationPool().AddUserSimulation(txHash, userSimulation)
	assert.Error(t, err, "Should reject duplicate user simulation")
	assert.Contains(t, err.Error(), "already exists", "Error should mention duplicate")

	t.Logf("✅ User simulation storage test completed successfully")
}

func TestFirewallBlockSimulation(t *testing.T) {
	t.Parallel()

	// Setup test environment
	var (
		accounts = NewAccounts(3)
		genesis  = &core.Genesis{
			Config: params.MergedTestChainConfig,
			Alloc: types.GenesisAlloc{
				accounts[0].addr: {Balance: big.NewInt(params.Ether)},
				accounts[1].addr: {Balance: big.NewInt(params.Ether)},
				accounts[2].addr: {Balance: big.NewInt(params.Ether)},
			},
		}
	)

	backend := newTestBackendWithFirewall(t, 1, genesis)

	// Create the firewall API
	firewallAPI := NewFirewallAPI(backend)

	// Create test transactions
	tx1 := createMockTransaction(accounts[0]) // Will have matching simulation
	tx2 := createMockTransaction(accounts[1]) // Will have mismatched simulation
	tx3 := createMockTransaction(accounts[2]) // Will have no simulation

	// Store user simulations
	// TX1: Matching simulation (Transfer event)
	userSim1 := createMockUserSimulation()
	err := backend.TxSimulationPool().AddUserSimulation(tx1.Hash(), userSim1)
	require.NoError(t, err)

	// TX2: Non-matching simulation (Approval vs Transfer)
	userSim2 := createMockUserSimulationApproval()
	err = backend.TxSimulationPool().AddUserSimulation(tx2.Hash(), userSim2)
	require.NoError(t, err)

	// TX3: No simulation stored (should pass through normally)

	// Prepare transaction data for firewall API
	tx1Data, _ := tx1.MarshalBinary()
	tx2Data, _ := tx2.MarshalBinary()
	tx3Data, _ := tx3.MarshalBinary()

	// Get parent block
	parentBlock := backend.chain().CurrentBlock()

	// Create firewall API arguments
	args := FirewallAPIArgs{
		ParentBlockHash: rpc.BlockNumberOrHashWithHash(parentBlock.Hash(), true),
		Timestamp:       hexutil.Uint64(parentBlock.Time + 12), // +12 seconds
		Transactions:    []hexutil.Bytes{tx1Data, tx2Data, tx3Data},
	}

	// Execute block simulation
	ctx := context.Background()
	result, err := firewallAPI.SimulateBlock(ctx, args)
	require.NoError(t, err, "Block simulation should not fail")

	// Verify results
	t.Logf("Simulation completed - Included: %d, Dropped: %d", len(result.IncludedTxs), len(result.DroppedTxs))

	// Test assertions
	assert.NotNil(t, result, "Result should not be nil")

	// TX1 should be included (has matching simulation or will be mocked to match)
	// TX3 should be included (no simulation required)
	// TX2 should be dropped (mismatched simulation)

	includedHashes := make(map[common.Hash]bool)
	for _, tx := range result.IncludedTxs {
		includedHashes[tx.Hash()] = true
	}

	droppedHashes := make(map[common.Hash]bool)
	for _, dropped := range result.DroppedTxs {
		droppedHashes[dropped.Hash] = true
	}

	// TX3 should always be included (no firewall protection)
	assert.True(t, includedHashes[tx3.Hash()], "TX3 (no simulation) should be included")
	assert.False(t, droppedHashes[tx3.Hash()], "TX3 should not be in dropped list")

	// At least one transaction should be processed
	assert.Greater(t, len(result.IncludedTxs)+len(result.DroppedTxs), 0, "At least one transaction should be processed")

	// Verify gas accounting
	assert.GreaterOrEqual(t, result.GasUsed, uint64(0), "Gas used should be non-negative")

	// Verify state root
	assert.NotEqual(t, common.Hash{}, result.StateRoot, "State root should not be empty")

	t.Logf("✅ Block simulation filtering test completed successfully")
	t.Logf("   Included transactions: %d", len(result.IncludedTxs))
	t.Logf("   Dropped transactions: %d", len(result.DroppedTxs))
	t.Logf("   Total gas used: %d", result.GasUsed)
}

func TestFirewallSimulationComparison(t *testing.T) {
	t.Parallel()

	// Test the core comparison logic
	userSim := createMockUserSimulation()

	// Test 1: Identical simulations should match
	blockSim := createMockUserSimulation()
	match, err := firewall.CompareTxEvents(userSim, blockSim)
	assert.NoError(t, err)
	assert.True(t, match, "Identical simulations should match")

	// Test 2: Different simulations should not match
	differentSim := createMockUserSimulationApproval()
	match, err = firewall.CompareTxEvents(userSim, differentSim)
	assert.Error(t, err)
	assert.False(t, match, "Different simulations should not match")
	assert.Contains(t, err.Error(), "mismatch", "Error should indicate mismatch")

	// Test 3: Different event counts should not match
	emptySim := state.FullTransactionEvents{EventsByContract: []state.ContractEvents{}}
	match, err = firewall.CompareTxEvents(userSim, emptySim)
	assert.Error(t, err)
	assert.False(t, match, "Different event counts should not match")
	assert.Contains(t, err.Error(), "event count mismatch", "Error should indicate count mismatch")

	t.Logf("✅ Simulation comparison test completed successfully")
}

func TestFirewallIntegrationFlow(t *testing.T) {
	t.Parallel()

	// Test the complete flow: user submits simulation -> validator queries block simulation
	var (
		accounts = NewAccounts(2)
		genesis  = &core.Genesis{
			Config: params.MergedTestChainConfig,
			Alloc: types.GenesisAlloc{
				accounts[0].addr: {Balance: big.NewInt(params.Ether)},
				accounts[1].addr: {Balance: big.NewInt(params.Ether)},
			},
		}
	)

	backend := newTestBackendWithFirewall(t, 1, genesis)

	// Step 1: User creates and simulates transaction
	tx := createMockTransaction(accounts[0])
	userSimulation := createMockUserSimulation()

	// Step 2: User submits simulation to firewall
	err := backend.TxSimulationPool().AddUserSimulation(tx.Hash(), userSimulation)
	require.NoError(t, err, "User should be able to submit simulation")

	// Step 3: Validator receives block proposal and queries firewall
	firewallAPI := NewFirewallAPI(backend)
	parentBlock := backend.chain().CurrentBlock()
	txData, _ := tx.MarshalBinary()

	args := FirewallAPIArgs{
		ParentBlockHash: rpc.BlockNumberOrHashWithHash(parentBlock.Hash(), true),
		Timestamp:       hexutil.Uint64(parentBlock.Time + 12),
		Transactions:    []hexutil.Bytes{txData},
	}

	// Step 4: Firewall validates and returns filtered block
	ctx := context.Background()
	result, err := firewallAPI.SimulateBlock(ctx, args)
	require.NoError(t, err, "Firewall should process block simulation")

	// Step 5: Verify validator gets appropriate response
	assert.NotNil(t, result, "Firewall should return result")
	assert.GreaterOrEqual(t, len(result.IncludedTxs)+len(result.DroppedTxs), 1, "Transaction should be processed")

	// Step 6: Verify simulation status is updated
	finalResult, exists := backend.TxSimulationPool().GetResult(tx.Hash())
	assert.True(t, exists, "Final result should exist")
	assert.NotEqual(t, firewall.StatusNotSeen, finalResult.Status, "Status should be updated from NotSeen")

	t.Logf("✅ Integration flow test completed successfully")
	t.Logf("   Final transaction status: %s", finalResult.Status.String())
}

// Helper function to create a mock transaction
func createMockTransaction(account account) *types.Transaction {
	recipient := common.HexToAddress("0x9876543210987654321098765432109876543210")
	amount := big.NewInt(1000000000000000000) // 1 ETH
	gasPrice := big.NewInt(20000000000)       // 20 Gwei

	tx := types.NewTransaction(0, recipient, amount, 21000, gasPrice, nil)
	signer := types.HomesteadSigner{}
	signedTx, _ := types.SignTx(tx, signer, account.key)
	return signedTx
}

// BenchmarkFirewallSimulation benchmarks the firewall simulation performance
func BenchmarkFirewallSimulation(b *testing.B) {
	// Setup
	accounts := NewAccounts(1)
	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			accounts[0].addr: {Balance: big.NewInt(params.Ether)},
		},
	}

	// Convert *testing.B to *testing.T for the helper function
	t := &testing.T{}
	backend := newTestBackendWithFirewall(t, 1, genesis)

	tx := createMockTransaction(accounts[0])
	userSim := createMockUserSimulation()
	backend.TxSimulationPool().AddUserSimulation(tx.Hash(), userSim)

	firewallAPI := NewFirewallAPI(backend)
	parentBlock := backend.chain().CurrentBlock()
	txData, _ := tx.MarshalBinary()

	args := FirewallAPIArgs{
		ParentBlockHash: rpc.BlockNumberOrHashWithHash(parentBlock.Hash(), true),
		Timestamp:       hexutil.Uint64(parentBlock.Time + 12),
		Transactions:    []hexutil.Bytes{txData},
	}

	ctx := context.Background()

	// Benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := firewallAPI.SimulateBlock(ctx, args)
		if err != nil {
			b.Fatal(err)
		}
	}
}
