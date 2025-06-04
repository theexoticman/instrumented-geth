package ethapi

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"

	// Needed for potential concurrent access if hooks run in parallel
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
)

// --- Configuration and Context (Keep or adapt as needed) ---

// ExecutionContext contains contextual infos for a transaction execution.
// Renamed from EVMLoggerContext for clarity.
type ExecutionContext struct {
	BlockHash   common.Hash // Hash of the block the tx is contained within (zero if dangling tx or call)
	BlockNumber *big.Int    // Number of the block the tx is contained within (zero if dangling tx or call)
	TxIndex     int         // Index of the transaction within a block (zero if dangling tx or call)
	TxHash      common.Hash // Hash of the transaction being traced (zero if dangling call)
}

// EventTracerConfig holds configuration options for the diff tracer.
// Extracted from the generic vm.Config for clarity, assuming these are specific to this tracer.
type EventTracerConfig struct {
	IsEventTracer bool `json:"IsEventTracer"` // If true, this tracer will return state modifications
	// Add any specific config options needed for the diff tracer here
	// e.g., MaxStorageKeysToCapture int
	// If no specific options, this struct might be empty or just use json.RawMessage
	RawJSON json.RawMessage // Keep raw config if needed for compatibility or complex options
}

// --- Core Tracer Logic and State ---

// EventTracer holds the state and implements the logic for diff tracing via hooks.
type EventTracer struct {
	logTracer    *tracer
	ctx          *ExecutionContext
	cfg          *EventTracerConfig
	fullTxEvents state.FullTransactionEvents

	// Intermediate state needed during execution
	currentDepth int
	vmError      error
	gasUsed      uint64
}

//
//
// FullTransactionEvents <- []ContractCallEvents <- []EventData
//
//

func NewEventTracer(blockNumber uint64) *EventTracer {
	return &EventTracer{
		fullTxEvents: NewTransactionEvents(),
		cfg: &EventTracerConfig{
			IsEventTracer: true,
		},
		logTracer: newTracer(true, blockNumber, common.Hash{}, common.Hash{}, 0),
		ctx: &ExecutionContext{
			BlockHash:   common.Hash{},
			BlockNumber: big.NewInt(0),
			TxIndex:     0,
			TxHash:      common.Hash{},
		},
	}
}

// It takes the execution context and configuration.
// It might also need the vm.StateDB to fetch initial states if not provided otherwise.
func NewTransactionEvents() state.FullTransactionEvents {
	// initialize transaction events tracker
	fullTransactionEvents := state.FullTransactionEvents{}

	// intiialize the slice of events
	fullTransactionEvents.EventsByContract = make([]state.ContractEvents, 0)
	return fullTransactionEvents

}

// reset prepares the tracer for the next transaction.
func (et *EventTracer) reset(txHash common.Hash, txIdx uint) {
	et.fullTxEvents = NewTransactionEvents()
	et.logTracer.reset(txHash, txIdx)
}

// GetHooks returns a populated Hooks struct pointing to the EventTracer's methods.
func (dr *EventTracer) GetHooks() *tracing.Hooks {
	return &tracing.Hooks{
		// VM events
		OnTxStart:       dr.OnTxStart,
		OnEnter:         dr.onEnter,
		OnExit:          dr.ExitHook,
		OnCodeChange:    dr.OnCodeChange,
		OnLog:           dr.OnLog,
		OnBalanceChange: dr.OnBalanceChangeHook,
	}
}

// GetResult returns the captured pre and post states.
func (dr *EventTracer) GetResult() (*DiffTracerResult, error) {

	// TODO: Handle event capture if needed
	eventsCopy := make(map[common.Address]*[]state.EventData)
	// Populate eventsCopy if events are captured

	return &DiffTracerResult{
		Events: eventsCopy, // Add captured events here
	}, dr.vmError // Return any captured VM error
}

// --- Hook Implementations ---

// OnTxStart is called at the beginning of the transaction execution.
func (dr *EventTracer) OnTxStart(vm *tracing.VMContext, tx *types.Transaction, from common.Address) {

	dr.vmError = nil
	dr.currentDepth = -1 // Start at -1 so first OnEnter makes depth 0
	dr.gasUsed = 0

	// initialize the events elements
	dr.fullTxEvents = NewTransactionEvents()
}

// OnEnter is called when the EVM enters a new frame (contract call).
func (et *EventTracer) onEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	et.logTracer.onEnter(depth, typ, from, to, input, gas, value)
}

// ExitHook is called when the EVM exits a frame.
func (et *EventTracer) ExitHook(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	et.logTracer.onExit(depth, output, gasUsed, err, reverted)
}

// OnOpcode is called before an opcode is executed.
func (dr *EventTracer) OpcodeHook(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	// TODO: evaluate if we need to capture the opcode here if we already have the logs hook

}

// FaultHook is called when the EVM encounters an error during opcode execution.
func (dr *EventTracer) FaultHook(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, depth int, err error) {
	// doesnt matter to us
}

// lets make balance change a specific event where the reason and the amouns are the identification.
// TODO: add caller as part of the event
func (et *EventTracer) OnBalanceChangeHook(addr common.Address, prev, new *big.Int, reason tracing.BalanceChangeReason) {

	// prevBytes  byte[];
	var prevBytes [32]byte
	var newBytes [32]byte

	if prev != nil {
		prev.FillBytes(prevBytes[:]) // Pass the array as a slice using [:]
	}
	if new != nil {
		new.FillBytes(newBytes[:]) // Pass the array as a slice using [:]
	}

	paramsForEvent := make([][32]byte, 0, 2)
	paramsForEvent = append(paramsForEvent, prevBytes)
	paramsForEvent = append(paramsForEvent, newBytes)

	balanceEvent := state.EventData{
		EventSigHash: tracing.GetBalanceChangeReasonHash(reason), // Use predefined hash
		Parameters:   paramsForEvent,
		// TODO: make Caller available and include

	}
	newEvents := state.ContractEvents{
		Address:        addr,
		ContractEvents: balanceEvent,
	}

	// Append the event
	et.fullTxEvents.EventsByContract = append(et.fullTxEvents.EventsByContract, newEvents)
}

func (dr *EventTracer) OnNonceChange(addr common.Address, prev, new uint64) {
	// Nothing here in term of events
	// Mayber Later create a nonce change event as nonce differences in transaction could reveal different patterns and reveal potential malicious behavior
}

func (dr *EventTracer) OnCodeChange(addr common.Address, prevHash common.Hash, prevCode []byte, newHash common.Hash, newCode []byte) {
	// from HOOKS definition CodeChangeHook is called when the code of an account changes.
	// TODO later, as we move to AA, we might want to capture code change.

}

func (dr *EventTracer) OnStorageChange(addr common.Address, slot, prev, new common.Hash) {
	// this is too low level, but we could, in some architecture patterns such as proxies, find malicious behaviors.
	// to be evaluated later.
}

// OnLog captures event data.
// event emitted by contract in the EVM.
func (et *EventTracer) OnLog(log *types.Log) {
	// capture the log normally
	et.logTracer.captureLog(log.Address, log.Topics, log.Data)

	// create a new custom event instance
	newContractEvent := state.ContractEvents{}
	newContractEvent.Address = log.Address
	newContractEvent.ContractEvents = parseEventData(log)

	// append to the transaction slice of events
	et.fullTxEvents.EventsByContract = append(et.fullTxEvents.EventsByContract, newContractEvent)
}

// func (t *tracer) captureLog(address common.Address, topics []common.Hash, data []byte) {
// 	t.logs[len(t.logs)-1] = append(t.logs[len(t.logs)-1], &types.Log{
// 		Address:     address,
// 		Topics:      topics,
// 		Data:        data,
// 		BlockNumber: t.blockNumber,
// 		BlockHash:   t.blockHash,
// 		TxHash:      t.txHash,
// 		TxIndex:     t.txIdx,
// 		Index:       uint(t.count),
// 	})
// 	t.count++
// }

// --- Helper methods ---

// ensurePostAccountExists initializes the post account entry if it doesn't exist.
// Must be called with lock held.
// func (dr *EventTracer) ensurePostAccountExists(addr common.Address) {
// 	if _, exists := dr.post[addr]; !exists {
// 		// Initialize based on pre-state if captured, otherwise empty
// 		preAcc, preExists := dr.pre[addr]
// 		if preExists {
// 			dr.post[addr] = copyTracerAccount(preAcc) // Start post from pre
// 		} else {
// 			// If pre-state wasn't captured (e.g., account initially empty), start fresh
// 			dr.post[addr] = &TracerAccount{
// 				Balance: new(big.Int), // Initialize balance to 0
// 				Storage: make(map[common.Hash]common.Hash),
// 			}
// 			// TODO: Consider fetching initial state from statedb here if needed
// 			// and pre-state capture isn't done elsewhere.
// 		}
// 	}
// }

// TODO: Implement capturePreStateIfNotExists, capturePreBalanceIfNotExists, etc.
// These methods would check if addr exists in dr.pre. If not, they would fetch
// the required state (balance, nonce, code, storage slot) from the vm.StateDB
// (which needs to be passed to the EventTracer) and populate the dr.pre map.
// Must be called with lock held. Example:
/*
func (dr *EventTracer) capturePreStateIfNotExists(addr common.Address) {
	if _, exists := dr.pre[addr]; !exists {
		if dr.statedb == nil {
			// Cannot capture pre-state without statedb
			// Log or handle this case appropriately
			// Maybe initialize with zero/empty state as a fallback?
			dr.pre[addr] = &TracerAccount{Balance: new(big.Int), Storage: make(map[common.Hash]common.Hash)}
			return
		}
		dr.pre[addr] = &TracerAccount{
			Balance: dr.statedb.GetBalance(addr).ToBig(), // Use uint256 version if available
			Nonce:   dr.statedb.GetNonce(addr),
			Code:    dr.statedb.GetCode(addr),
			Storage: make(map[common.Hash]common.Hash), // Pre-storage captured lazily via OnStorageChange/OnOpcode
		}
	}
}
func (dr *EventTracer) capturePreStorageIfNotExists(addr common.Address, slot, value common.Hash) {
    dr.ensurePreAccountExists(addr) // Make sure base account exists in pre
    if dr.pre[addr].Storage == nil {
        dr.pre[addr].Storage = make(map[common.Hash]common.Hash)
    }
    if _, exists := dr.pre[addr].Storage[slot]; !exists {
        dr.pre[addr].Storage[slot] = value // Store the *previous* value
    }
}
// ensurePreAccountExists is needed by capturePreStorageIfNotExists
func (dr *EventTracer) ensurePreAccountExists(addr common.Address) {
    if _, exists := dr.pre[addr]; !exists {
        dr.capturePreStateIfNotExists(addr)
    }
}
*/

// copyTracerAccount creates a deep copy of a TracerAccount.
func copyTracerAccount(orig *TracerAccount) *TracerAccount {
	if orig == nil {
		return nil
	}
	cpy := &TracerAccount{
		Nonce: orig.Nonce,
	}
	if orig.Balance != nil {
		cpy.Balance = new(big.Int).Set(orig.Balance)
	} else {
		cpy.Balance = new(big.Int) // Ensure non-nil balance
	}
	if orig.Code != nil {
		cpy.Code = common.CopyBytes(orig.Code)
	}
	if orig.Storage != nil {
		cpy.Storage = make(map[common.Hash]common.Hash, len(orig.Storage))
		for k, v := range orig.Storage {
			cpy.Storage[k] = v // Hashes are value types, direct copy is fine
		}
	} else {
		cpy.Storage = make(map[common.Hash]common.Hash) // Ensure non-nil map
	}
	return cpy
}

// --- Utility Functions (Keep as is) ---

const (
	memoryPadLimit = 1024 * 1024
)

// func GetMemoryCopyPadded(m *Memory, offset, size uint64) ([]byte, error) {
// 	// Implementation remains the same
// 	if size == 0 {
// 		return []byte{}, nil
// 	}
// 	if int(offset+size) < m.Len() { // slice fully inside memory
// 		return m.GetCopy(offset, size), nil
// 	}
// 	// Check for potential overflow before calculating paddingNeeded
// 	if offset+size < offset { // Overflow occurred
// 		return nil, fmt.Errorf("memory offset/size overflow: offset=%d, size=%d", offset, size)
// 	}
// 	paddingNeeded := int(offset+size) - m.Len()
// 	if paddingNeeded > memoryPadLimit {
// 		return nil, fmt.Errorf("reached limit for padding memory slice: %d", paddingNeeded)
// 	}
// 	cpy := make([]byte, size)
// 	// Check for overflow before calculating overlap
// 	memLenU64 := uint64(m.Len())
// 	if offset >= memLenU64 { // Offset is beyond memory length, all padding
// 		return cpy, nil // Return zero-filled slice
// 	}
// 	overlap := memLenU64 - offset
// 	if overlap > size { // Should not happen if initial check passed, but good practice
// 		overlap = size
// 	}
// 	copy(cpy, m.GetPtr(offset, overlap))
// 	return cpy, nil
// }

// --- Data Structures (Keep as is or adapt) ---

type DiffTracerResult struct {
	Events map[common.Address]*[]state.EventData `json:"events,omitempty"` // Keep if event capture is implemented
}

type TracerAccount struct {
	Balance *big.Int                    `json:"balance,omitempty"`
	Code    []byte                      `json:"code,omitempty"`
	Nonce   uint64                      `json:"nonce,omitempty"`
	Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
}

// Exists, UnmarshalJSON, MarshalJSON, DebugPrint, AreDiffTracerResultsEqual etc. remain the same

func (a *TracerAccount) Exists() bool {
	return a.Nonce > 0 || len(a.Code) > 0 || len(a.Storage) > 0 || (a.Balance != nil && a.Balance.Sign() != 0)
}

func (a *TracerAccount) UnmarshalJSON(input []byte) error {
	type account struct {
		Balance *hexutil.Big                `json:"balance,omitempty"`
		Code    *hexutil.Bytes              `json:"code,omitempty"`
		Nonce   *uint64                     `json:"nonce,omitempty"`
		Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
	}
	var dec account
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	// Ensure fields are initialized even if nil in JSON
	if a.Balance == nil {
		a.Balance = new(big.Int)
	}
	if a.Storage == nil {
		a.Storage = make(map[common.Hash]common.Hash)
	}

	if dec.Balance != nil {
		a.Balance.Set((*big.Int)(dec.Balance))
	}
	if dec.Code != nil {
		a.Code = *dec.Code
	}
	if dec.Nonce != nil {
		a.Nonce = *dec.Nonce
	}
	if dec.Storage != nil {
		// Clear existing storage before assigning new map
		// or merge if that's the desired behavior
		a.Storage = dec.Storage
	}
	return nil
}

func (t *TracerAccount) DebugPrint() {
	fmt.Printf("Balance: %s\n", t.Balance.Text(16)) // Print balance in hexadecimal
	fmt.Printf("Nonce: %x\n", t.Nonce)              // Print nonce in hexadecimal
	fmt.Printf("Code Len: %d\n", len(t.Code))       // Print code length

	fmt.Println("Storage:")
	for key, value := range t.Storage {
		fmt.Printf("  Key: %s, Value: %s\n", key.Hex(), value.Hex())
	}
}

// func (d *DiffTracerResult) DebugPrint() {
// 	fmt.Println("\n--- Diff Tracer Pre ---")
// 	for address, tracer := range d.Pre {
// 		fmt.Printf("Address: %s\n", address.Hex())
// 		tracer.DebugPrint()
// 	}
// 	fmt.Println("\n--- Diff Tracer Post ---")
// 	for address, tracer := range d.Post {
// 		fmt.Printf("Address: %s\n", address.Hex())
// 		tracer.DebugPrint()
// 	}
// 	// TODO: Add event printing if needed
// 	fmt.Println("-----------------------")
// }

func (a TracerAccount) MarshalJSON() ([]byte, error) {
	type account struct {
		Balance *hexutil.Big                `json:"balance,omitempty"`
		Code    hexutil.Bytes               `json:"code,omitempty"`
		Nonce   *hexutil.Uint64             `json:"nonce,omitempty"` // Use pointer for omitempty
		Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
	}
	var enc account

	// Only include fields if they are non-zero/non-empty
	if a.Balance != nil && a.Balance.Sign() != 0 {
		enc.Balance = (*hexutil.Big)(a.Balance)
	}
	if len(a.Code) > 0 {
		enc.Code = a.Code
	}
	if a.Nonce > 0 {
		nonce := hexutil.Uint64(a.Nonce)
		enc.Nonce = &nonce
	}
	if len(a.Storage) > 0 {
		enc.Storage = a.Storage
	}

	return json.Marshal(&enc)
}

func areTracerAccountsEqual(a, b *TracerAccount) bool {
	if a == nil || b == nil {
		return a == b // Both nil is equal, one nil is not
	}
	// Handle nil balances explicitly
	balA := a.Balance
	if balA == nil {
		balA = big.NewInt(0)
	}
	balB := b.Balance
	if balB == nil {
		balB = big.NewInt(0)
	}

	return balA.Cmp(balB) == 0 &&
		reflect.DeepEqual(a.Code, b.Code) && // DeepEqual handles nil slices correctly
		a.Nonce == b.Nonce &&
		reflect.DeepEqual(a.Storage, b.Storage) // DeepEqual handles nil maps correctly
}

// func AreDiffTracerResultsEqual(a, b *DiffTracerResult) bool {
// 	if a == nil || b == nil {
// 		return a == b
// 	}
// 	if len(a.Post) != len(b.Post) || len(a.Pre) != len(b.Pre) {
// 		return false
// 	}

// 	for addr, accA := range a.Post {
// 		accB, exists := b.Post[addr]
// 		if !exists || !areTracerAccountsEqual(accA, accB) {
// 			return false
// 		}
// 	}
// 	// Check keys missing in a but present in b
// 	for addr := range b.Post {
// 		if _, exists := a.Post[addr]; !exists {
// 			return false
// 		}
// 	}

// 	for addr, accA := range a.Pre {
// 		accB, exists := b.Pre[addr]
// 		if !exists || !areTracerAccountsEqual(accA, accB) {
// 			return false
// 		}
// 	}
// 	// Check keys missing in a but present in b
// 	for addr := range b.Pre {
// 		if _, exists := a.Pre[addr]; !exists {
// 			return false
// 		}
// 	}

// 	// TODO: Compare Events if captured
// 	// return reflect.DeepEqual(a.Events, b.Events)

// 	return true
// }

// parseEventData converts a types.Log into the EventData struct.
func parseEventData(log *types.Log) state.EventData {
	// initialize a new ContractEvent data structure
	event := state.EventData{}

	if len(log.Topics) > 0 {
		event.EventSigHash = log.Topics[0] // Assign common.Hash directly
	}

	// extract sig hash and  topics
	numTopics := 0
	if len(log.Topics) > 1 { // Exclude event signature hash
		numTopics = len(log.Topics) - 1
	}

	// log.Data is []byte. We need to chunk it into [][32]byte.
	dataParams := bytesToParameters(log.Data) // bytesToParameters returns [][32]byte
	totalParams := numTopics + len(dataParams)

	event.Parameters = make([][32]byte, 0, totalParams) // Pre-allocate slice as [][32]byte

	// Add indexed parameters (topics)
	for i := 1; i < len(log.Topics); i++ { // Start from index 1
		event.Parameters = append(event.Parameters, [32]byte(log.Topics[i])) // common.Hash.Bytes32() returns [32]byte
	}

	// Add non-indexed parameters (data)
	// dataParams is already [][32]byte
	event.Parameters = append(event.Parameters, dataParams...)

	return event
}

func bytesToParameters(data []byte) [][32]byte { // Changed from hexutil.Bytes to []byte for log.Data
	// Ensure the data length is a multiple of 32
	if len(data)%32 != 0 {
		// It's common for EVM data to not be perfectly padded,
		// handle this case or decide on error/padding strategy.
		// For now, let's panic as it indicates an issue with data source or assumptions.
		// A more robust solution might involve padding or returning an error.
		// panic("data length is not a multiple of 32 bytes")
		// Alternative: return empty or partially filled if that's valid for your use case
	}

	// Create a slice to hold the parameters
	numParams := len(data) / 32
	parameters := make([][32]byte, numParams)

	// Split the data into 32-byte chunks
	for i := 0; i < numParams; i++ {
		var chunk [32]byte
		copy(chunk[:], data[i*32:(i+1)*32]) // Copy 32 bytes into the fixed array
		parameters[i] = chunk               // Assign to the result slice
	}

	return parameters
}

func (et *EventTracer) Logs() []*types.Log {
	return et.logTracer.logs[0]
}
