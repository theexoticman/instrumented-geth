package ethapi

import (
	"fmt"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// SimulatedChainStore stores persists simulated transactions, blocks, receipts and txs for local-only chain state.
// it is used to make demos on mainnet without having to:
// 1. pay for gas on mainnet
// 2. moving funds during demo and having to move them back to the original account
// 3. this node will provide clients the state as if the simulation was run on mainnet.
// so you wallet connect to this node, will look like the transaction actually happened on mainnet but it did not.

type SimulatedChainStore struct {
	txMu         sync.RWMutex
	blocksMu     sync.RWMutex
	receiptsMu   sync.RWMutex
	accountsMu   sync.RWMutex
	blocks       []*types.Block                     // Ordered simulated blocks
	blockMap     map[common.Hash]*types.Block       // block hash -> block
	txs          map[common.Hash]*types.Transaction // tx hash -> tx
	receipts     map[common.Hash]*types.Receipt     // tx hash -> receipt
	blockTxs     map[uint64][]common.Hash           // block number -> list of tx hashes
	accounts     map[common.Address]*SimulatedAccount
	fullTxEvents map[common.Hash]FullTransactionEvents
}

type SimulatedAccount struct {
	Address common.Address
	Balance *uint256.Int
	Storage map[common.Hash]common.Hash
}

// NewSimulatedChainStore creates a new empty simulated store.
func NewSimulatedChainStore() *SimulatedChainStore {
	return &SimulatedChainStore{
		blockMap:     make(map[common.Hash]*types.Block),
		txs:          make(map[common.Hash]*types.Transaction),
		receipts:     make(map[common.Hash]*types.Receipt),
		blockTxs:     make(map[uint64][]common.Hash),
		accounts:     make(map[common.Address]*SimulatedAccount),
		fullTxEvents: make(map[common.Hash]FullTransactionEvents),
	}
}

// GetTransaction returns a transaction by its hash.
func (s *SimulatedChainStore) GetTxEvents(txHash common.Hash) (FullTransactionEvents, bool) {
	s.txMu.RLock()
	defer s.txMu.RUnlock()
	tx, ok := s.fullTxEvents[txHash]
	return tx, ok
}

// GetTransaction returns a transaction by its hash.
func (s *SimulatedChainStore) GetTransaction(txHash common.Hash) (*types.Transaction, bool) {
	s.txMu.RLock()
	defer s.txMu.RUnlock()
	tx, ok := s.txs[txHash]
	return tx, ok
}

// GetReceipt returns a simulated receipt by tx hash.
func (s *SimulatedChainStore) GetReceipt(txHash common.Hash) (*types.Receipt, bool) {
	s.receiptsMu.RLock()
	defer s.receiptsMu.RUnlock()
	r, ok := s.receipts[txHash]
	return r, ok
}
func (s *SimulatedChainStore) GetLatestBlock() (*types.Block, bool) {
	s.blocksMu.RLock()
	defer s.blocksMu.RUnlock()
	block := s.blocks[len(s.blocks)-1]
	return block, block != nil
}

// GetBlockByNumber returns a simulated block by block number.
func (s *SimulatedChainStore) GetBlockByNumber(num uint64) (*types.Block, bool) {
	s.blocksMu.RLock()
	defer s.blocksMu.RUnlock()

	if num >= uint64(len(s.blocks)) {
		return nil, false
	}
	block := s.blocks[num]
	return block, block != nil
}

// GetBlockByHash returns a simulated block by hash.
// func (s *SimulatedChainStore) GetBlockByHash(hash common.Hash) (*types.Block, bool) {
// 	s.blocksMu.RLock()
// 	defer s.blocksMu.RUnlock()
// 	block, ok := s.blockMap[hash]
// 	return block, ok
// }

// GetTransactionsByBlockNumber returns all txs for a simulated block.
func (s *SimulatedChainStore) GetTransactionsByBlockNumber(num uint64) ([]*types.Transaction, bool) {
	s.txMu.RLock()
	defer s.txMu.RUnlock()

	hashes, ok := s.blockTxs[num]
	if !ok {
		return nil, false
	}
	var txs []*types.Transaction
	for _, h := range hashes {
		if tx, ok := s.txs[h]; ok {
			txs = append(txs, tx)
		}
	}
	return txs, true
}
func (s *SimulatedChainStore) StoreTxEvents(txHash common.Hash, events FullTransactionEvents) {
	s.fullTxEvents[txHash] = events
}

// StoreSimulatedAccountState extracts the state of all touched accounts from the given state.
// Used to extract the state of the accounts from the final state after simulation.
func StoreSimulatedAccountState(_state *state.StateDB) map[common.Address]*SimulatedAccount {
	touched := make(map[common.Address]*SimulatedAccount)

	for addr := range _state.Mutations() {
		obj := _state.GetStateObject(addr)
		if obj == nil {
			continue // account was deleted
		}
		account := &SimulatedAccount{
			Address: obj.Address(),
			Balance: obj.Balance(),
			Storage: make(map[common.Hash]common.Hash),
		}

		_state.ForEachStorage(obj.Address(), func(key, value common.Hash) bool {
			account.Storage[key] = value
			return true
		})

		touched[addr] = account
	}

	return touched
}

// AddAccount inserts or updates the state of an account in the simulated store.
func (s *SimulatedChainStore) CreateSimulatedAccount(account *SimulatedAccount) {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()

	if s.accounts == nil {
		s.accounts = make(map[common.Address]*SimulatedAccount)
	}

	existing, ok := s.accounts[account.Address]
	if !ok {
		// First time seeing this account
		s.accounts[account.Address] = account
		return
	}

	// Optionally merge the state (or just replace)
	existing.Balance = account.Balance

	if existing.Storage == nil {
		existing.Storage = make(map[common.Hash]common.Hash)
	}
	for k, v := range account.Storage {
		existing.Storage[k] = v
	}
}

// StoreBlock stores a simulated block and all related txs and receipts.
// It now accepts an optional originalTxHash to use as the storage key for the transaction and receipt.
func (s *SimulatedChainStore) StoreBlock(results *simBlockResult, originalTxHash *common.Hash) {
	s.blocksMu.Lock()
	defer s.blocksMu.Unlock()
	s.txMu.Lock()
	defer s.txMu.Unlock()
	s.receiptsMu.Lock()
	defer s.receiptsMu.Unlock()
	block := results.Block
	receipts := results.Receipts

	s.blocks = append(s.blocks, block)
	s.blockMap[block.Hash()] = block

	blockNumber := block.NumberU64()
	// Ensure the blockTxs slice for this number exists
	if _, exists := s.blockTxs[blockNumber]; !exists {
		s.blockTxs[blockNumber] = []common.Hash{}
	}

	for i, tx := range block.Transactions() {

		// Determine the key to use for storage.
		// Use the provided original hash if available, otherwise use the hash of the reconstructed tx.
		var storageKey common.Hash
		if originalTxHash != nil && i == 0 { // Assuming originalTxHash corresponds to the first (and likely only) tx in this context
			storageKey = *originalTxHash
		} else {
			storageKey = tx.Hash() // Hash of reconstructed tx
		}

		fmt.Println("storageKey", storageKey)
		os.Stdout.Sync()

		s.txs[storageKey] = tx
		s.receipts[storageKey] = receipts[i]
		s.blockTxs[blockNumber] = append(s.blockTxs[blockNumber], storageKey)

		// Store the tx events

		events := results.Calls[i].FTE
		s.StoreTxEvents(storageKey, events)
	}
}

// GetAccount returns the stored simulated account state for a given address.
func (s *SimulatedChainStore) GetAccount(addr common.Address) *SimulatedAccount {
	s.accountsMu.RLock()
	defer s.accountsMu.RUnlock()

	return s.accounts[addr]
}

func (s *SimulatedChainStore) Blocks() []*types.Block {
	return s.blocks
}
