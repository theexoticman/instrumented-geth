package firewall

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// SimulationStatus represents the validation lifecycle of a transaction.
type SimulationStatus int

const (
	// StatusNotSeen means the transaction has not been seen by the firewall.
	StatusNotSeen SimulationStatus = iota
	// StatusUserSimReceived means a user simulation has been received, pending block inclusion.
	StatusUserSimReceived
	// StatusMatch means the block simulation matched the user simulation successfully.
	StatusMatch
	// StatusMismatch means the block simulation did not match the user simulation.
	StatusMismatch
)

func (s SimulationStatus) String() string {
	switch s {
	case StatusNotSeen:
		return "not seen"
	case StatusUserSimReceived:
		return "user simulation received, pending validation"
	case StatusMatch:
		return "validation successful: simulation matched"
	case StatusMismatch:
		return "validation failed: simulation mismatched"
	default:
		return "unknown"
	}
}

// SimulationResult holds the outcome of a firewall validation check.
type SimulationResult struct {
	Status SimulationStatus
	// Match is true if the user-provided and block-generated simulations were equivalent.
	Match bool
	// Reason provides a human-readable explanation for a simulation mismatch.
	Reason string
}

// TxSimulationPool stores user-provided simulations and the results of firewall checks.
// It is safe for concurrent use.
type TxSimulationPool struct {
	// A mutex is necessary because this pool will be written to by the RPC handler
	// (AddUserSimulation) and read from by the miner (IsUserSimulated, CompareAndStoreResult)
	// concurrently.
	mu sync.RWMutex

	userSimulations  map[common.Hash]state.FullTransactionEvents
	blockSimulations map[common.Hash]state.FullTransactionEvents
	results          map[common.Hash]*SimulationResult
}

// NewTxSimulationPool creates and initializes a new simulation pool.
func NewTxSimulationPool() *TxSimulationPool {
	log.Info("Firewall: Creating new transaction simulation pool")
	return &TxSimulationPool{
		userSimulations:  make(map[common.Hash]state.FullTransactionEvents),
		blockSimulations: make(map[common.Hash]state.FullTransactionEvents),
		results:          make(map[common.Hash]*SimulationResult),
	}
}

// AddUserSimulation stores a user-provided simulation and sets its initial status.
// This is typically called from an RPC endpoint when a user submits their simulation.
func (p *TxSimulationPool) AddUserSimulation(canonicalId common.Hash, simulation state.FullTransactionEvents) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Firewall: Processing user simulation submission",
		"txHash", canonicalId.Hex(),
		"eventCount", len(simulation.EventsByContract))

	// Log detailed simulation content
	for i, contractEvent := range simulation.EventsByContract {
		log.Info("Firewall: User simulation event details",
			"txHash", canonicalId.Hex(),
			"eventIndex", i,
			"contractAddress", contractEvent.Address.Hex(),
			"eventSigHash", contractEvent.ContractEvents.EventSigHash.Hex(),
			"parameterCount", len(contractEvent.ContractEvents.Parameters))

		// Log each parameter value
		for j, param := range contractEvent.ContractEvents.Parameters {
			log.Info("Firewall: User simulation event parameter",
				"txHash", canonicalId.Hex(),
				"eventIndex", i,
				"parameterIndex", j,
				"parameterValue", hex.EncodeToString(param[:]))
		}
	}

	if _, exists := p.userSimulations[canonicalId]; exists {
		log.Warn("Firewall: User simulation already exists for transaction",
			"txHash", canonicalId.Hex())
		return fmt.Errorf("user simulation for tx %s already exists", canonicalId.Hex())
	}

	p.userSimulations[canonicalId] = simulation
	p.results[canonicalId] = &SimulationResult{
		Status: StatusUserSimReceived,
	}

	log.Info("Firewall: User simulation successfully stored",
		"txHash", canonicalId.Hex(),
		"status", StatusUserSimReceived.String(),
		"totalStoredSimulations", len(p.userSimulations))

	return nil
}

// IsUserSimulated checks if a transaction has a user-provided simulation and is
// intended to be protected by the firewall. This is called by the miner.
func (p *TxSimulationPool) ShouldSimulateInBlock(txHash common.Hash) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	_, exists := p.results[txHash]
	if !exists {
		// Log a small sample of tracked hashes to debug mismatches
		sample := make([]string, 0, 5)
		i := 0
		for h := range p.results {
			if i >= 5 {
				break
			}
			sample = append(sample, h.Hex())
			i++
		}
		log.Info("Firewall: ShouldSimulateInBlock MISS",
			"txHash", txHash.Hex(),
			"tracked", len(p.results),
			"sampleTracked", sample)
	} else {
		log.Info("Firewall: ShouldSimulateInBlock HIT",
			"txHash", txHash.Hex(),
			"tracked", len(p.results))
	}
	return exists
}

// IsTransactionSafe checks the tx against the stored simulation using canonical ID.
func (p *TxSimulationPool) IsTransactionSafe(canonicalID common.Hash, blockFTE state.FullTransactionEvents) (*SimulationResult, error) {
	log.Info("Firewall: Starting transaction safety validation", "canonicalID", canonicalID.Hex())

	result, err := p.compareAndStoreResult(canonicalID, blockFTE)
	if err != nil {
		log.Error("Firewall:  Transaction safety validation failed", "canonicalID", canonicalID.Hex(), "error", err.Error())
	} else if result != nil {
		log.Info("Firewall:  Transaction safety validation completed",
			"canonicalID", canonicalID.Hex(),
			"status", result.Status.String(),
			"match", result.Match,
			"reason", result.Reason)
	}
	return result, err
}

// compareAndStoreResult fetches the user-provided simulation by canonical ID.
func (p *TxSimulationPool) compareAndStoreResult(canonicalID common.Hash, blockFTE state.FullTransactionEvents) (*SimulationResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Firewall:  Starting detailed simulation comparison",
		"canonicalID", canonicalID.Hex(),
		"blockEventCount", len(blockFTE.EventsByContract))

	userFTE, exists := p.userSimulations[canonicalID]
	if !exists {
		log.Error("Firewall:  User simulation not found for transaction",
			"canonicalID", canonicalID.Hex(),
			"availableSimulations", len(p.userSimulations))
		return nil, fmt.Errorf("user simulation for canonicalID %s not found", canonicalID.Hex())
	}

	log.Info("Firewall: 📊 Found user simulation for comparison",
		"canonicalID", canonicalID.Hex(),
		"userEventCount", len(userFTE.EventsByContract),
		"blockEventCount", len(blockFTE.EventsByContract))

	result, exists := p.results[canonicalID]
	if !exists {
		log.Error("Firewall:  Internal state inconsistency - result entry not found",
			"canonicalID", canonicalID.Hex())
		return nil, fmt.Errorf("internal state inconsistency: result entry for canonicalID %s not found", canonicalID.Hex())
	}

	// Track block-level FTE
	p.blockSimulations[canonicalID] = blockFTE

	log.Info("Firewall: 🔬 Beginning deep event comparison", "canonicalID", canonicalID.Hex())

	areSimilar, err := CompareTxEvents(userFTE, blockFTE, canonicalID)
	if areSimilar {
		result.Status = StatusMatch
		result.Match = true
		result.Reason = ""
		log.Info("Firewall:   SIMULATION MATCH! Transaction is safe", "canonicalID", canonicalID.Hex(), "status", result.Status.String())
	} else {
		result.Status = StatusMismatch
		result.Match = false
		result.Reason = err.Error()
		log.Warn("Firewall:   SIMULATION MISMATCH! Transaction is potentially malicious",
			"canonicalID", canonicalID.Hex(), "status", result.Status.String(), "mismatchReason", result.Reason)
	}

	log.Info("Firewall:  Pool statistics after comparison",
		"canonicalID", canonicalID.Hex(),
		"totalUserSimulations", len(p.userSimulations),
		"totalBlockSimulations", len(p.blockSimulations),
		"totalResults", len(p.results))

	return result, nil
}

// GetResult retrieves the final validation result for a transaction.
// This can be used by a debug API to return the mismatch reason.
func (p *TxSimulationPool) GetResult(txHash common.Hash) (*SimulationResult, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result, exists := p.results[txHash]
	if !exists {
		log.Debug("Firewall: No result found for transaction",
			"txHash", txHash.Hex())
		return nil, false
	}

	log.Info("Firewall: Retrieved validation result",
		"txHash", txHash.Hex(),
		"status", result.Status.String(),
		"match", result.Match,
		"reason", result.Reason)

	// Return a copy to prevent race conditions on the returned struct.
	resCopy := *result
	return &resCopy, true
}

// GetStatus retrieves the current validation status for a transaction.
func (p *TxSimulationPool) GetStatus(txHash common.Hash) SimulationStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if result, exists := p.results[txHash]; exists {
		log.Debug("Firewall: Retrieved transaction status",
			"txHash", txHash.Hex(),
			"status", result.Status.String())
		return result.Status
	}

	log.Debug("Firewall: Transaction not seen by firewall",
		"txHash", txHash.Hex(),
		"status", StatusNotSeen.String())
	return StatusNotSeen
}
func CompareTxEvents(userFTE, blockFTE state.FullTransactionEvents, txHash common.Hash) (bool, error) {
	// Apply filters first
	origUserCount := len(userFTE.EventsByContract)
	origBlockCount := len(blockFTE.EventsByContract)
	userFTE = filterFTE(userFTE)
	blockFTE = filterFTE(blockFTE)

	log.Info("Firewall: 🔬 Starting comprehensive event comparison (filtered)",
		"txHash", txHash.Hex(),
		"userEventCount", len(userFTE.EventsByContract),
		"blockEventCount", len(blockFTE.EventsByContract),
		"userFiltered", origUserCount-len(userFTE.EventsByContract),
		"blockFiltered", origBlockCount-len(blockFTE.EventsByContract))

	// 1. Verify that the total number of events emitted is the same.
	if len(userFTE.EventsByContract) != len(blockFTE.EventsByContract) {
		mismatchMsg := fmt.Sprintf("event count mismatch: user simulation has %d events, block simulation has %d",
			len(userFTE.EventsByContract), len(blockFTE.EventsByContract))

		log.Warn("Firewall:  Event count mismatch detected",
			"txHash", txHash.Hex(),
			"userEventCount", len(userFTE.EventsByContract),
			"blockEventCount", len(blockFTE.EventsByContract),
			"mismatch", mismatchMsg)

		return false, fmt.Errorf(mismatchMsg)
	}

	log.Info("Firewall:  Event count match confirmed",
		"txHash", txHash.Hex(),
		"eventCount", len(userFTE.EventsByContract))

	// 2. Compare each event in order of execution.
	for i := 0; i < len(userFTE.EventsByContract); i++ {
		userContractEvent := userFTE.EventsByContract[i]
		blockContractEvent := blockFTE.EventsByContract[i]

		log.Info("Firewall:  Comparing individual event",
			"txHash", txHash.Hex(),
			"eventIndex", i,
			"userContractAddr", userContractEvent.Address.Hex(),
			"blockContractAddr", blockContractEvent.Address.Hex(),
			"userEventSig", userContractEvent.ContractEvents.EventSigHash.Hex(),
			"blockEventSig", blockContractEvent.ContractEvents.EventSigHash.Hex())

		if ok, err := compareContractEvent(userContractEvent, blockContractEvent, txHash, i); !ok {
			mismatchMsg := fmt.Sprintf("mismatch at event index %d: %v", i, err)
			log.Warn("Firewall:  Event mismatch found",
				"txHash", txHash.Hex(),
				"eventIndex", i,
				"mismatch", mismatchMsg,
				"detailedError", err.Error())
			return false, fmt.Errorf(mismatchMsg)
		}

		log.Info("Firewall:  Event match confirmed",
			"txHash", txHash.Hex(),
			"eventIndex", i)
	}

	log.Info("Firewall:  ALL EVENTS MATCH! Complete validation success",
		"txHash", txHash.Hex(),
		"totalEventsCompared", len(userFTE.EventsByContract))

	return true, nil
}

// compareContractEvent checks if two individual contract events are equivalent.
// It compares the emitting contract's address and the event data itself.
func compareContractEvent(userCE, blockCE state.ContractEvents, txHash common.Hash, eventIndex int) (bool, error) {
	log.Info("Firewall:  Comparing contract event details",
		"txHash", txHash.Hex(),
		"eventIndex", eventIndex,
		"userAddress", userCE.Address.Hex(),
		"blockAddress", blockCE.Address.Hex())

	// 1. Compare the address of the contract that emitted the event.
	if userCE.Address != blockCE.Address {
		mismatchMsg := fmt.Sprintf("contract address mismatch: expected %s, got %s", userCE.Address.Hex(), blockCE.Address.Hex())
		log.Warn("Firewall:  Contract address mismatch",
			"txHash", txHash.Hex(),
			"eventIndex", eventIndex,
			"expectedAddress", userCE.Address.Hex(),
			"actualAddress", blockCE.Address.Hex(),
			"mismatch", mismatchMsg)
		return false, fmt.Errorf(mismatchMsg)
	}

	log.Info("Firewall:  Contract address match confirmed",
		"txHash", txHash.Hex(),
		"eventIndex", eventIndex,
		"contractAddress", userCE.Address.Hex())

	// 2. Compare the content of the event.
	return compareEventData(userCE.ContractEvents, blockCE.ContractEvents, txHash, eventIndex)
}

// compareEventData checks if two event data payloads are equivalent.
// It compares the event signature hash and all of the event parameters.
func compareEventData(userED, blockED state.EventData, txHash common.Hash, eventIndex int) (bool, error) {
	log.Info("Firewall: Comparing event data in detail",
		"txHash", txHash.Hex(),
		"eventIndex", eventIndex,
		"userEventSig", userED.EventSigHash.Hex(),
		"blockEventSig", blockED.EventSigHash.Hex(),
		"userParamCount", len(userED.Parameters),
		"blockParamCount", len(blockED.Parameters))

	// 1. Compare the event signature hash.
	if userED.EventSigHash != blockED.EventSigHash {
		mismatchMsg := fmt.Sprintf("event signature hash mismatch: expected %s, got %s", userED.EventSigHash.Hex(), blockED.EventSigHash.Hex())
		log.Warn("Firewall:  Event signature hash mismatch",
			"txHash", txHash.Hex(),
			"eventIndex", eventIndex,
			"expectedSigHash", userED.EventSigHash.Hex(),
			"actualSigHash", blockED.EventSigHash.Hex(),
			"mismatch", mismatchMsg)
		return false, fmt.Errorf(mismatchMsg)
	}

	log.Info("Firewall:  Event signature hash match confirmed",
		"txHash", txHash.Hex(),
		"eventIndex", eventIndex,
		"eventSigHash", userED.EventSigHash.Hex())

	// 2. Compare the number of parameters.
	if len(userED.Parameters) != len(blockED.Parameters) {
		mismatchMsg := fmt.Sprintf("event parameter count mismatch for event %s: expected %d, got %d",
			userED.EventSigHash.Hex(), len(userED.Parameters), len(blockED.Parameters))
		log.Warn("Firewall:  Parameter count mismatch",
			"txHash", txHash.Hex(),
			"eventIndex", eventIndex,
			"eventSigHash", userED.EventSigHash.Hex(),
			"expectedParamCount", len(userED.Parameters),
			"actualParamCount", len(blockED.Parameters),
			"mismatch", mismatchMsg)
		return false, fmt.Errorf(mismatchMsg)
	}

	log.Info("Firewall:  Parameter count match confirmed",
		"txHash", txHash.Hex(),
		"eventIndex", eventIndex,
		"parameterCount", len(userED.Parameters))

	// 3. Compare each parameter value.
	for i := 0; i < len(userED.Parameters); i++ {
		log.Info("Firewall:  Comparing parameter",
			"txHash", txHash.Hex(),
			"eventIndex", eventIndex,
			"parameterIndex", i,
			"userParam", hex.EncodeToString(userED.Parameters[i][:]),
			"blockParam", hex.EncodeToString(blockED.Parameters[i][:]))

		if userED.Parameters[i] != blockED.Parameters[i] {
			mismatchMsg := fmt.Sprintf("event parameter mismatch at index %d for event %s: expected %s, got %s",
				i, userED.EventSigHash.Hex(), hex.EncodeToString(userED.Parameters[i][:]), hex.EncodeToString(blockED.Parameters[i][:]))
			log.Warn("Firewall:  Parameter value mismatch",
				"txHash", txHash.Hex(),
				"eventIndex", eventIndex,
				"parameterIndex", i,
				"eventSigHash", userED.EventSigHash.Hex(),
				"expectedParam", hex.EncodeToString(userED.Parameters[i][:]),
				"actualParam", hex.EncodeToString(blockED.Parameters[i][:]),
				"mismatch", mismatchMsg)
			return false, fmt.Errorf(mismatchMsg)
		}

		log.Info("Firewall:  Parameter match confirmed",
			"txHash", txHash.Hex(),
			"eventIndex", eventIndex,
			"parameterIndex", i,
			"parameterValue", hex.EncodeToString(userED.Parameters[i][:]))
	}

	log.Info("Firewall:  ALL PARAMETERS MATCH! Event data validation successful",
		"txHash", txHash.Hex(),
		"eventIndex", eventIndex,
		"eventSigHash", userED.EventSigHash.Hex(),
		"totalParametersCompared", len(userED.Parameters))

	return true, nil
}

// CanonicalTxID computes a signature-independent identifier for a tx.
// PoC: only uses to, nonce, value, gas, and input data. Excludes sender and fee fields.
func CanonicalTxID(tx *types.Transaction, _ *params.ChainConfig, _ *types.Header) common.Hash {
	enc := []byte{}
	put := func(b []byte) { enc = append(enc, b...) }
	putU64 := func(x uint64) { put(new(big.Int).SetUint64(x).Bytes()) }
	putBig := func(b *big.Int) {
		if b != nil {
			put(b.Bytes())
		}
	}
	putAddr := func(a *common.Address) {
		if a != nil {
			put(a.Bytes())
		} else {
			put(make([]byte, 20))
		}
	}

	// Sender intentionally excluded. Fees intentionally excluded.
	putAddr(tx.To())
	putU64(tx.Nonce())
	putBig(tx.Value())
	put(tx.Data())

	return crypto.Keccak256Hash(enc)
}

// CanonicalTxID...

// Filter out gas/validator events by signature during comparison only.
var filteredEventSignatures = map[common.Hash]struct{}{
	common.HexToHash("0xed620e74005ef5b6859a850d3371a1c2363c06aea619dd9d62dbd50e77175344"): {},
	common.HexToHash("0xbcf852bd5973413005fcca294c13b8104b16f51c288a60710ca8ec990d5076f4"): {},
	common.HexToHash("0x0d17a004887fb911f81bd40baddcdba0a0df2c6270be1da65b89239f89ab8f89"): {},
}

func filterFTE(fte state.FullTransactionEvents) state.FullTransactionEvents {
	out := state.FullTransactionEvents{EventsByContract: make([]state.ContractEvents, 0, len(fte.EventsByContract))}
	for _, ce := range fte.EventsByContract {
		if _, skip := filteredEventSignatures[ce.ContractEvents.EventSigHash]; skip {
			log.Info("Firewall: Filtering event from comparison",
				"eventSigHash", ce.ContractEvents.EventSigHash.Hex(),
				"address", ce.Address.Hex())
			continue
		}
		out.EventsByContract = append(out.EventsByContract, ce)
	}
	return out
}
