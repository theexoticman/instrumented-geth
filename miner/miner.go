// Copyright 2014 The go-ethereum Authors
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

// Package miner implements Ethereum block creation and mining.
package miner

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
)

// Backend wraps all methods required for mining. Only full node is capable
// to offer all the functions here.
type Backend interface {
	BlockChain() *core.BlockChain
	TxPool() *txpool.TxPool
	TxSimulationPool() interface{}
}

// Add a new interface for firewall operations
type FirewallAPI interface {
	SimulateBlock(ctx context.Context, args interface{}) (interface{}, error)
}

// Config is the configuration parameters of mining.
type Config struct {
	Etherbase           common.Address `toml:"-"`          // Deprecated
	PendingFeeRecipient common.Address `toml:"-"`          // Address for pending block rewards.
	ExtraData           hexutil.Bytes  `toml:",omitempty"` // Block extra data set by the miner
	GasCeil             uint64         // Target gas ceiling for mined blocks.
	GasPrice            *big.Int       // Minimum gas price for mining a transaction
	Recommit            time.Duration  // The time interval for miner to re-create mining work.
	ExternalRPC         string         // External RPC endpoint to forward filtered transactions
}

// DefaultConfig contains default settings for miner.
var DefaultConfig = Config{
	GasCeil:  36_000_000,
	GasPrice: big.NewInt(params.GWei / 1000),

	// The default recommit time is chosen as two seconds since
	// consensus-layer usually will wait a half slot of time(6s)
	// for payload generation. It should be enough for Geth to
	// run 3 rounds.
	Recommit: 2 * time.Second,
}

// Miner is the main object which takes care of submitting new work to consensus
// engine and gathering the sealing result.
type Miner struct {
	confMu      sync.RWMutex // The lock used to protect the config fields: GasCeil, GasTip and Extradata
	config      *Config
	chainConfig *params.ChainConfig
	engine      consensus.Engine
	txpool      *txpool.TxPool
	prio        []common.Address // A list of senders to prioritize
	chain       *core.BlockChain
	pending     *pending
	pendingMu   sync.Mutex // Lock protects the pending block

	// Firewall simulation support
	backend Backend // Keep reference to backend for firewall API access

	// Add firewall API as a field
	firewallAPI FirewallAPI // Add this field
}

// New creates a new miner with the provided configuration
func New(backend Backend, config *Config, engine consensus.Engine, firewallAPI FirewallAPI) *Miner {
	return &Miner{
		config:      config,
		chainConfig: backend.BlockChain().Config(),
		engine:      engine,
		txpool:      backend.TxPool(),
		chain:       backend.BlockChain(), // ← ADD THIS LINE
		backend:     backend,
		firewallAPI: firewallAPI,
		pending:     &pending{},
	}
}

// Pending returns the currently pending block and associated receipts, logs
// and statedb. The returned values can be nil in case the pending block is
// not initialized.
func (miner *Miner) Pending() (*types.Block, types.Receipts, *state.StateDB) {
	pending := miner.getPending()
	if pending == nil {
		return nil, nil, nil
	}
	return pending.block, pending.receipts, pending.stateDB.Copy()
}

// SetExtra sets the content used to initialize the block extra field.
func (miner *Miner) SetExtra(extra []byte) error {
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra exceeds max length. %d > %v", len(extra), params.MaximumExtraDataSize)
	}
	miner.confMu.Lock()
	miner.config.ExtraData = extra
	miner.confMu.Unlock()
	return nil
}

// SetPrioAddresses sets a list of addresses to prioritize for transaction inclusion.
func (miner *Miner) SetPrioAddresses(prio []common.Address) {
	miner.confMu.Lock()
	miner.prio = prio
	miner.confMu.Unlock()
}

// SetGasCeil sets the gaslimit to strive for when mining blocks post 1559.
// For pre-1559 blocks, it sets the ceiling.
func (miner *Miner) SetGasCeil(ceil uint64) {
	miner.confMu.Lock()
	miner.config.GasCeil = ceil
	miner.confMu.Unlock()
}

// SetGasTip sets the minimum gas tip for inclusion.
func (miner *Miner) SetGasTip(tip *big.Int) error {
	miner.confMu.Lock()
	miner.config.GasPrice = tip
	miner.confMu.Unlock()
	return nil
}

// BuildPayload builds the payload according to the provided parameters.
func (miner *Miner) BuildPayload(args *BuildPayloadArgs, witness bool) (*Payload, error) {
	return miner.buildPayload(args, witness)
}

// getPending retrieves the pending block based on the current head block.
// The result might be nil if pending generation is failed.
func (miner *Miner) getPending() *newPayloadResult {
	header := miner.chain.CurrentHeader()
	miner.pendingMu.Lock()
	defer miner.pendingMu.Unlock()
	if cached := miner.pending.resolve(header.Hash()); cached != nil {
		return cached
	}

	var (
		timestamp  = uint64(time.Now().Unix())
		withdrawal types.Withdrawals
	)
	if miner.chainConfig.IsShanghai(new(big.Int).Add(header.Number, big.NewInt(1)), timestamp) {
		withdrawal = []*types.Withdrawal{}
	}
	ret := miner.generateWork(&GenerateParams{
		Timestamp:   timestamp,
		ForceTime:   false,
		ParentHash:  header.Hash(),
		Coinbase:    miner.config.PendingFeeRecipient,
		Random:      common.Hash{},
		Withdrawals: withdrawal,
		BeaconRoot:  nil,
		NoTxs:       false,
	}, false) // we will never make a witness for a pending block
	if ret.err != nil {
		return nil
	}
	miner.pending.update(header.Hash(), ret)
	return ret
}

// Add these public methods for simulation mode
func (miner *Miner) PrepareSimulationWork(genParams *GenerateParams, witness bool) (*Environment, error) {
	return miner.prepareWork(genParams, witness)
}

func (miner *Miner) FillTransactionsSimulateMode(interrupt *atomic.Int32, env *Environment) error {
	return miner.fillTransactionsSimulateMode(interrupt, env)
}

// Add these type aliases to make them accessible

type Environment = environment

// Make the generateParams fields public
type GenerateParams struct {
	Timestamp   uint64            // Make public
	ParentHash  common.Hash       // Make public
	Coinbase    common.Address    // Make public
	NoTxs       bool              // Make public
	ForceTime   bool              // Make public
	Withdrawals types.Withdrawals // Make public
	BeaconRoot  *common.Hash      // Make public
	Random      common.Hash       // Make public
}

// Add accessor methods
func (env *Environment) GetTransactions() []*types.Transaction {
	return env.txs
}

func (env *Environment) GetDroppedTxs() []*ethapi.DroppedTxInfo {
	// This will be populated by the fillTransactionsSimulateMode
	return nil // For now
}
