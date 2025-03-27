package ethapi

import (
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
)

// SimulatedChainStore stores simulated blocks, receipts and txs for local-only chain state.
type SimulatedChainStore struct {
	txMu          sync.RWMutex
	blocksMu      sync.RWMutex
	receiptsMu    sync.RWMutex
	blocks        []*types.Block                     // Ordered simulated blocks
	blockMap      map[common.Hash]*types.Block       // block hash -> block
	txs           map[common.Hash]*types.Transaction // tx hash -> tx
	receipts      map[common.Hash]*types.Receipt     // tx hash -> receipt
	blockTxs      map[uint64][]common.Hash           // block number -> list of tx hashes
	accountsState map[common.Address]AccountState
}

type AccountState struct {
	Balance *big.Int
	Nonce   uint64
	Code    []byte
	Storage map[common.Hash]common.Hash
}

// NewSimulatedChainStore creates a new empty simulated store.
func NewSimulatedChainStore() *SimulatedChainStore {
	return &SimulatedChainStore{
		blockMap: make(map[common.Hash]*types.Block),
		txs:      make(map[common.Hash]*types.Transaction),
		receipts: make(map[common.Hash]*types.Receipt),
		blockTxs: make(map[uint64][]common.Hash),
	}
}

// AddBlock stores a simulated block and all related txs and receipts.
func (s *SimulatedChainStore) AddBlock(block *types.Block, receipts []*types.Receipt) {
	s.blocksMu.Lock()
	defer s.blocksMu.Unlock()

	s.blocks = append(s.blocks, block)
	s.blockMap[block.Hash()] = block

	blockNumber := block.NumberU64()

	for i, tx := range block.Transactions() {
		txHash := tx.Hash()
		s.txs[txHash] = tx
		s.receipts[txHash] = receipts[i]
		s.blockTxs[blockNumber] = append(s.blockTxs[blockNumber], txHash)
	}
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
func (s *SimulatedChainStore) GetBlockByHash(hash common.Hash) (*types.Block, bool) {
	s.blocksMu.RLock()
	defer s.blocksMu.RUnlock()
	block, ok := s.blockMap[hash]
	return block, ok
}

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

func (s *SimulatedChainStore) AddSimulatedResult(result *simBlockResult) {
	if result == nil || result.Block == nil {
		return
	}

	s.blocksMu.Lock()
	defer s.blocksMu.Unlock()

	block := result.Block
	s.blocks = append(s.blocks, block)
	s.blockMap[block.Hash()] = block

	// Extract transactions and map them
	txs := block.Transactions()
	for _, tx := range txs {
		s.txs[tx.Hash()] = tx
	}

	// Build and store receipts from simCallResult
	for i, call := range result.Calls {
		// safety check in case fewer txs than calls
		if i >= len(txs) {
			break
		}
		tx := txs[i]
		receipt := call.ToReceipt(tx, block.Hash(), block.NumberU64())
		s.receipts[tx.Hash()] = receipt
	}
}

func ExtractTouchedAccountStates(_state *state.StateDB) map[common.Address]*AccountState {
	touched := make(map[common.Address]*AccountState)

	for addr := range _state.Mutations() {
		obj := _state.GetStateObject(addr)
		if obj == nil {
			continue // account was deleted
		}
		account := &AccountState{
			Balance: obj.Balance().ToBig(),
			Nonce:   obj.Nonce(),
			Code:    obj.Code(),
			Storage: make(map[common.Hash]common.Hash),
		}

		obj.ForEachStorage(func(key, value common.Hash) bool {
			account.Storage[key] = value
			return true
		})

		touched[addr] = account
	}

	return touched
}
