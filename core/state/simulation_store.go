package state

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
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
	Address  common.Address
	Balance  *uint256.Int
	Storage  map[common.Hash]common.Hash
	Code     []byte
	Nonce    uint64
	CodeHash []byte
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
func (s *SimulatedChainStore) AddAccountBalance(addr common.Address, amount *uint256.Int) {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
	if s.accounts[addr] == nil {
		s.accounts[addr] = &SimulatedAccount{
			Address: addr,
			Balance: amount,
		}
	}
	s.accounts[addr].Balance = new(uint256.Int).Add(s.accounts[addr].Balance, amount)
}

func (s *SimulatedChainStore) SetAccountBalance(addr common.Address, amount *uint256.Int) {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
	if s.accounts[addr] == nil {
		s.accounts[addr] = &SimulatedAccount{
			Address: addr,
			Balance: amount,
		}
	}
	s.accounts[addr].Balance = amount
}

func (s *SimulatedChainStore) SubAccountBalance(addr common.Address, amount *uint256.Int) {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
	if s.accounts[addr] == nil {
		s.accounts[addr] = &SimulatedAccount{
			Address: addr,
			Balance: new(uint256.Int),
		}
	}
	if s.accounts[addr].Balance.Cmp(amount) < 0 {
		s.accounts[addr].Balance = new(uint256.Int)
	} else {
		s.accounts[addr].Balance = new(uint256.Int).Sub(s.accounts[addr].Balance, amount)
	}
}

func (s *SimulatedChainStore) UpdateAccountNonce(addr common.Address, nonce uint64) {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
	if s.accounts[addr] == nil {
		s.accounts[addr] = &SimulatedAccount{
			Address: addr,
			Nonce:   nonce,
		}
	}
	s.accounts[addr].Nonce = nonce
}
func (s *SimulatedChainStore) UpdateAccountCode(addr common.Address, code []byte) {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
	if s.accounts[addr] == nil {
		s.accounts[addr] = &SimulatedAccount{
			Address: addr,
			Code:    code,
		}
	}
	s.accounts[addr].Code = code
}

func (s *SimulatedChainStore) SetStorage(addr common.Address, storage map[common.Hash]common.Hash) {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
	if s.accounts[addr] == nil {
		s.accounts[addr] = &SimulatedAccount{
			Address: addr,
			Storage: make(map[common.Hash]common.Hash),
		}
	}
	for key, value := range storage {
		s.accounts[addr].Storage[key] = value
	}
}
func (s *SimulatedChainStore) DeleteAccount(addr common.Address) {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
	delete(s.accounts, addr)
}

// CreateOrUpdateAccounts creates or updates the accounts in the store.
func (s *SimulatedChainStore) CreateOrUpdateAccounts(_state *StateDB) {
	// accounts in state are loaded from the store, so here we only need to put in the store from the statedb
	if s.accounts == nil {
		s.accounts = make(map[common.Address]*SimulatedAccount)
	}
	// iterate over all accounts modified during the tx
	for addr := range _state.Mutations() {

		obj := _state.GetStateObject(addr)
		if obj == nil {
			continue
		}
		if s.accounts[addr] == nil {
			s.accounts[addr] = &SimulatedAccount{
				Address:  addr,
				Balance:  obj.Balance(),
				Storage:  make(map[common.Hash]common.Hash),
				Code:     obj.Code(),
				Nonce:    obj.Nonce(),
				CodeHash: obj.CodeHash(),
			}
		} else {

		}

		// iterate over the storage of the account
		// _state.ForEachStorage(addr, func(key, value common.Hash) bool {
		// 	fmt.Println("\nCreateOrUpdateAccounts")
		// 	fmt.Println("addr", addr.Hex())
		// 	fmt.Println("key", key.Hex())
		// 	fmt.Println("value", value.Hex())
		// 	os.Stdout.Sync()
		// 	s.accounts[addr].Storage[key] = value
		// 	return true
		// })

		// fmt.Println("_______")
		// fmt.Println("NEW TX")
		// fmt.Println("_______")
		// fmt.Println("account address", s.accounts[addr].Address.Hex())
		// fmt.Println("account Nonce", s.accounts[addr].Nonce)
		// fmt.Println("account Balance", s.accounts[addr].Balance)
		// fmt.Println("account Has Code", len(s.accounts[addr].Code) > 2)
		// fmt.Println("account Code hash", s.accounts[addr].CodeHash)
		// os.Stdout.Sync()
	}
}

// StoreBlock stores a simulated block and all related txs and receipts.
// It now accepts an optional originalTxHash to use as the storage key for the transaction and receipt.
func (s *SimulatedChainStore) StoreBlock(results *SimBlockResult, originalTxHash *common.Hash) {
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
	if s.accounts[addr] == nil {
		s.accounts[addr] = &SimulatedAccount{
			Address: addr,
			Balance: new(uint256.Int),
		}
	}
	return s.accounts[addr]
}

func (s *SimulatedChainStore) Blocks() []*types.Block {
	return s.blocks
}

// SimBlockResult is the result of a simulated block.
type SimBlockResult struct {
	FullTx      bool
	ChainConfig *params.ChainConfig
	Block       *types.Block
	Calls       []SimCallResult

	Receipts []*types.Receipt
	// Senders is a map of transaction hashes to their Senders.
	Senders map[common.Hash]common.Address
}

// FullTransactionEvents track the order of the events emitted in a transaction in a slice
// order of events follow first in last out (FILO) order as they are appended to the slice
type FullTransactionEvents struct {
	EventsByContract []ContractEvents `json:"eventsByContract"`
}

// ContractEvents Track an event instance emitted by a contract within the evm
// Every new event create a new
type ContractEvents struct {
	Address        common.Address `json:"address"`        // Capitalized and added JSON tag
	ContractEvents EventData      `json:"contractEvents"` // Capitalized and added JSON tag
}

type EventData struct {
	EventSigHash common.Hash `json:"eventSigHash"` // Kept as common.Hash
	Parameters   [][32]byte  `json:"parameters"`   // Kept as [][32]byte
	// TODO: add caller, as of now, not available in types.Log
}

// SimCallResult is the result of a simulated call.
type SimCallResult struct {
	ReturnValue hexutil.Bytes         `json:"returnData"`
	Logs        []*types.Log          `json:"logs"`
	FTE         FullTransactionEvents `json:"fullTransactionEvents"`
	GasUsed     hexutil.Uint64        `json:"gasUsed"`
	Status      hexutil.Uint64        `json:"status"`
	Error       *CallError            `json:"error,omitempty"`
}

// TODO better clean
type CallError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Data    string `json:"data,omitempty"`
}

// Custom JSON marshaling for EventData
func (ed EventData) MarshalJSON() ([]byte, error) {
	// Convert common.Hash to hex string
	eventSigHashHex := ed.EventSigHash.Hex()

	// Convert [][32]byte to []string (hex strings)
	parametersHex := make([]string, len(ed.Parameters))
	for i, param := range ed.Parameters {
		parametersHex[i] = "0x" + hex.EncodeToString(param[:])
	}

	// Create a temporary struct for JSON marshaling
	type eventDataJSON struct {
		EventSigHash string   `json:"eventSigHash"`
		Parameters   []string `json:"parameters"`
	}

	temp := eventDataJSON{
		EventSigHash: eventSigHashHex,
		Parameters:   parametersHex,
	}

	return json.Marshal(temp)
}

// Custom JSON unmarshaling for EventData
func (ed *EventData) UnmarshalJSON(data []byte) error {
	// Create a temporary struct for JSON unmarshaling
	type eventDataJSON struct {
		EventSigHash string   `json:"eventSigHash"`
		Parameters   []string `json:"parameters"`
	}

	var temp eventDataJSON
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Convert hex string back to common.Hash
	ed.EventSigHash = common.HexToHash(temp.EventSigHash)

	// Convert []string (hex strings) back to [][32]byte
	ed.Parameters = make([][32]byte, len(temp.Parameters))
	for i, paramHex := range temp.Parameters {
		// Remove "0x" prefix if present
		if strings.HasPrefix(paramHex, "0x") {
			paramHex = paramHex[2:]
		}

		// Decode hex string to bytes
		paramBytes, err := hex.DecodeString(paramHex)
		if err != nil {
			return fmt.Errorf("invalid hex parameter at index %d: %v", i, err)
		}

		// Ensure it's exactly 32 bytes
		if len(paramBytes) != 32 {
			return fmt.Errorf("parameter at index %d must be exactly 32 bytes, got %d", i, len(paramBytes))
		}

		// Copy to [32]byte
		copy(ed.Parameters[i][:], paramBytes)
	}

	return nil
}

func (s *SimulatedChainStore) UpdateAccountStorage(addr common.Address, key common.Hash, value common.Hash) {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
	if s.accounts[addr] == nil {
		s.accounts[addr] = &SimulatedAccount{
			Address: addr,
			Storage: make(map[common.Hash]common.Hash),
		}
	}
	if s.accounts[addr].Storage == nil {
		s.accounts[addr].Storage = make(map[common.Hash]common.Hash)
	}
	s.accounts[addr].Storage[key] = value
}

func (r *SimCallResult) MarshalJSON() ([]byte, error) {
	type callResultAlias SimCallResult
	// Marshal logs to be an empty array instead of nil when empty
	if r.Logs == nil {
		r.Logs = []*types.Log{}
	}
	return json.Marshal((*callResultAlias)(r))
}

/**
*
* Used only in the simulate mode with local mining.
*
*
 */
func (call SimCallResult) ToReceipt(tx *types.Transaction, blockHash common.Hash, blockNumber uint64) *types.Receipt {
	return &types.Receipt{
		Type:              tx.Type(),
		CumulativeGasUsed: uint64(call.GasUsed),
		Logs:              call.Logs,
		TxHash:            tx.Hash(),
		ContractAddress:   common.Address{}, // or actual if contract creation
		GasUsed:           uint64(call.GasUsed),
		BlockHash:         blockHash,
		BlockNumber:       big.NewInt(int64(blockNumber)),
		Status:            uint64(call.Status),
	}
}
