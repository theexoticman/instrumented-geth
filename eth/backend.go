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

// Package eth implements the Ethereum protocol.
package eth

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/filtermaps"
	"github.com/ethereum/go-ethereum/core/firewall"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/pruner"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/blobpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/txpool/locals"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/eth/gasprice"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/internal/shutdowncheck"
	"github.com/ethereum/go-ethereum/internal/version"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/dnsdisc"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	gethversion "github.com/ethereum/go-ethereum/version"
)

// Config contains the configuration options of the ETH protocol.
// Deprecated: use ethconfig.Config instead.
type Config = ethconfig.Config

// FirewallAPIWrapper wraps the ethapi.FirewallAPI to match the miner.FirewallAPI interface
type FirewallAPIWrapper struct {
	api *ethapi.FirewallAPI
}

func (w *FirewallAPIWrapper) SimulateBlock(ctx context.Context, args interface{}) (interface{}, error) {
	// Convert the args to the proper type
	firewallArgs, ok := args.(ethapi.FirewallAPIArgs)
	if !ok {
		// Try to convert from the inline~ struct we created in worker.go
		if argsMap, ok := args.(struct {
			ParentBlockHash interface{}     `json:"parentBlockHash"`
			Transactions    []hexutil.Bytes `json:"transactions"`
		}); ok {
			// Type assert ParentBlockHash to the correct type
			parentBlockHash, ok := argsMap.ParentBlockHash.(rpc.BlockNumberOrHash)
			if !ok {
				return nil, fmt.Errorf("invalid ParentBlockHash type")
			}

			firewallArgs = ethapi.FirewallAPIArgs{
				ParentBlockHash: parentBlockHash,
				Transactions:    argsMap.Transactions,
			}
		} else {
			return nil, fmt.Errorf("invalid arguments type for firewall API")
		}
	}

	result, err := w.api.SimulateBlock(ctx, firewallArgs)
	if err != nil {
		return nil, err
	}

	// Convert the result to a map[string]interface{} to avoid import cycles
	return map[string]interface{}{
		"includedTxs": result.IncludedTxs,
		"droppedTxs":  result.DroppedTxs,
	}, nil
}

type SimulationResult struct {
	IncludedTxs []*types.Transaction
	DroppedTxs  []*ethapi.DroppedTxInfo
}

type generateParams struct {
	timestamp  uint64
	parentHash common.Hash
	coinbase   common.Address
	noTxs      bool
}

// Add methods to support the transaction pool API
func (s *Ethereum) IsIntentGuard() bool {
	return s.isIntentGuard
}

// PrivateTxPool is a simple FIFO pool for private transactions from eth_sendRawTransaction
type PrivateTxPool struct {
	mu      sync.RWMutex
	pending map[common.Hash]*types.Transaction // tx hash -> transaction
	order   []common.Hash                      // insertion order (FIFO)
	maxSize int                                // size limit
}

// NewPrivateTxPool creates a new private transaction pool
func NewPrivateTxPool(maxSize int) *PrivateTxPool {
	return &PrivateTxPool{
		pending: make(map[common.Hash]*types.Transaction),
		order:   make([]common.Hash, 0),
		maxSize: maxSize,
	}
}

// AddTransaction adds a transaction to the private pool with minimal validation
func (p *PrivateTxPool) AddTransaction(tx *types.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	hash := tx.Hash()

	// Check if transaction already exists (avoid duplicates)
	if _, exists := p.pending[hash]; exists {
		return fmt.Errorf("transaction %s already exists in private pool", hash.Hex())
	}

	// FIFO eviction if at capacity
	for len(p.order) >= p.maxSize {
		oldestHash := p.order[0]
		delete(p.pending, oldestHash)
		p.order = p.order[1:]
	}

	// Add transaction as-is (SendRawTransaction already validated it)
	p.pending[hash] = tx
	p.order = append(p.order, hash)

	log.Debug("Added transaction to private pool",
		"hash", hash.Hex(),
		"nonce", tx.Nonce(),
		"chainId", tx.ChainId(),
		"poolSize", len(p.pending))

	return nil
}

// GetPendingTransactions returns up to limit transactions in FIFO order
func (p *PrivateTxPool) GetPendingTransactions(limit int) []*types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*types.Transaction, 0, limit)
	for i, hash := range p.order {
		if i >= limit {
			break
		}
		if tx, exists := p.pending[hash]; exists {
			result = append(result, tx)
		} else {
			log.Error("Transaction not found in private pool", "hash", hash.Hex())
		}
	}
	return result
}

// RemoveTransaction removes a transaction by hash
func (p *PrivateTxPool) RemoveTransaction(hash common.Hash) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.pending[hash]; !exists {
		return false
	}

	delete(p.pending, hash)
	for i, h := range p.order {
		if h == hash {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
	return true
}

// GetTransaction returns a transaction by hash
func (p *PrivateTxPool) GetTransaction(hash common.Hash) *types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pending[hash]
}

// Count returns the number of transactions in the pool
func (p *PrivateTxPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.pending)
}

// Add to Ethereum struct
type Ethereum struct {
	// core protocol objects
	config         *ethconfig.Config
	txPool         *txpool.TxPool
	localTxTracker *locals.TxTracker
	blockchain     *core.BlockChain

	handler *handler
	discmix *enode.FairMix
	dropper *dropper

	// DB interfaces
	chainDb ethdb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	filterMaps      *filtermaps.FilterMaps
	closeFilterMaps chan chan struct{}

	APIBackend *EthAPIBackend

	miner    *miner.Miner
	gasPrice *big.Int

	networkID     uint64
	netRPCService *ethapi.NetAPI

	p2pServer *p2p.Server

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)

	shutdownTracker *shutdowncheck.ShutdownTracker // Tracks if and when the node has shutdown ungracefully

	// simulate mode
	isIntentGuard    bool
	simStore         *state.SimulatedChainStore
	txSimulationPool *firewall.TxSimulationPool

	// Private transaction pool for intent guard mode
	privateTxPool *PrivateTxPool
}

// New creates a new Ethereum object (including the initialisation of the common Ethereum object),
// whose lifecycle will be managed by the provided node.
func New(stack *node.Node, config *ethconfig.Config) (*Ethereum, error) {
	// Ensure configuration values are compatible and sane
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	if !config.HistoryMode.IsValid() {
		return nil, fmt.Errorf("invalid history mode %d", config.HistoryMode)
	}
	if config.Miner.GasPrice == nil || config.Miner.GasPrice.Sign() <= 0 {
		log.Warn("Sanitizing invalid miner gas price", "provided", config.Miner.GasPrice, "updated", ethconfig.Defaults.Miner.GasPrice)
		config.Miner.GasPrice = new(big.Int).Set(ethconfig.Defaults.Miner.GasPrice)
	}
	if config.NoPruning && config.TrieDirtyCache > 0 {
		if config.SnapshotCache > 0 {
			config.TrieCleanCache += config.TrieDirtyCache * 3 / 5
			config.SnapshotCache += config.TrieDirtyCache * 2 / 5
		} else {
			config.TrieCleanCache += config.TrieDirtyCache
		}
		config.TrieDirtyCache = 0
	}
	log.Info("Allocated trie memory caches", "clean", common.StorageSize(config.TrieCleanCache)*1024*1024, "dirty", common.StorageSize(config.TrieDirtyCache)*1024*1024)

	chainDb, err := stack.OpenDatabaseWithFreezer("chaindata", config.DatabaseCache, config.DatabaseHandles, config.DatabaseFreezer, "eth/db/chaindata/", false)
	if err != nil {
		return nil, err
	}
	scheme, err := rawdb.ParseStateScheme(config.StateScheme, chainDb)
	if err != nil {
		return nil, err
	}
	// Try to recover offline state pruning only in hash-based.
	if scheme == rawdb.HashScheme {
		if err := pruner.RecoverPruning(stack.ResolvePath(""), chainDb); err != nil {
			log.Error("Failed to recover state", "error", err)
		}
	}

	// Here we determine genesis hash and active ChainConfig.
	// We need these to figure out the consensus parameters and to set up history pruning.
	chainConfig, _, err := core.LoadChainConfig(chainDb, config.Genesis)
	if err != nil {
		return nil, err
	}
	engine, err := ethconfig.CreateConsensusEngine(chainConfig, chainDb)
	if err != nil {
		return nil, err
	}
	// Set networkID to chainID by default.
	networkID := config.NetworkId
	if networkID == 0 {
		networkID = chainConfig.ChainID.Uint64()
	}

	// Assemble the Ethereum object.
	eth := &Ethereum{
		config:          config,
		chainDb:         chainDb,
		eventMux:        stack.EventMux(),
		accountManager:  stack.AccountManager(),
		engine:          engine,
		networkID:       networkID,
		gasPrice:        config.Miner.GasPrice,
		p2pServer:       stack.Server(),
		discmix:         enode.NewFairMix(0),
		shutdownTracker: shutdowncheck.NewShutdownTracker(chainDb),
		isIntentGuard:   config.IntentGuard,
	}
	// Intent Guard mode (formerly simulate mode)
	if config.IntentGuard {
		// eth.simStore = state.NewSimulatedChainStore()
		eth.txSimulationPool = firewall.NewTxSimulationPool()

		// Initialize private transaction pool
		eth.privateTxPool = NewPrivateTxPool(config.PrivatePoolSize)
		log.Info("Intent Guard mode enabled", "privatePoolSize", config.PrivatePoolSize)
	}
	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	var dbVer = "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}
	log.Info("Initialising Ethereum protocol", "network", networkID, "dbversion", dbVer)

	// Create BlockChain object.
	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > core.BlockChainVersion {
			return nil, fmt.Errorf("database version is v%d, Geth %s only supports v%d", *bcVersion, version.WithMeta, core.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < core.BlockChainVersion {
			if bcVersion != nil { // only print warning on upgrade, not on init
				log.Warn("Upgrade blockchain database version", "from", dbVer, "to", core.BlockChainVersion)
			}
			rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
		}
	}
	var (
		vmConfig = vm.Config{
			EnablePreimageRecording: config.EnablePreimageRecording,
		}
		cacheConfig = &core.CacheConfig{
			TrieCleanLimit:      config.TrieCleanCache,
			TrieCleanNoPrefetch: config.NoPrefetch,
			TrieDirtyLimit:      config.TrieDirtyCache,
			TrieDirtyDisabled:   config.NoPruning,
			TrieTimeLimit:       config.TrieTimeout,
			SnapshotLimit:       config.SnapshotCache,
			Preimages:           config.Preimages,
			StateHistory:        config.StateHistory,
			StateScheme:         scheme,
			ChainHistoryMode:    config.HistoryMode,
		}
	)
	if config.VMTrace != "" {
		traceConfig := json.RawMessage("{}")
		if config.VMTraceJsonConfig != "" {
			traceConfig = json.RawMessage(config.VMTraceJsonConfig)
		}
		t, err := tracers.LiveDirectory.New(config.VMTrace, traceConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create tracer %s: %v", config.VMTrace, err)
		}
		vmConfig.Tracer = t
	}
	// Override the chain config with provided settings.
	var overrides core.ChainOverrides
	if config.OverridePrague != nil {
		overrides.OverridePrague = config.OverridePrague
	}
	if config.OverrideVerkle != nil {
		overrides.OverrideVerkle = config.OverrideVerkle
	}

	eth.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, config.Genesis, &overrides, eth.engine, vmConfig, &config.TransactionHistory)

	if err != nil {
		return nil, err
	}

	// Initialize filtermaps log index.
	fmConfig := filtermaps.Config{
		History:        config.LogHistory,
		Disabled:       config.LogNoHistory,
		ExportFileName: config.LogExportCheckpoints,
		HashScheme:     scheme == rawdb.HashScheme,
	}
	chainView := eth.newChainView(eth.blockchain.CurrentBlock())
	historyCutoff, _ := eth.blockchain.HistoryPruningCutoff()
	var finalBlock uint64
	if fb := eth.blockchain.CurrentFinalBlock(); fb != nil {
		finalBlock = fb.Number.Uint64()
	}
	eth.filterMaps = filtermaps.NewFilterMaps(chainDb, chainView, historyCutoff, finalBlock, filtermaps.DefaultParams, fmConfig)
	eth.closeFilterMaps = make(chan chan struct{})

	// TxPool
	if config.TxPool.Journal != "" {
		config.TxPool.Journal = stack.ResolvePath(config.TxPool.Journal)
	}
	legacyPool := legacypool.New(config.TxPool, eth.blockchain)

	if config.BlobPool.Datadir != "" {
		config.BlobPool.Datadir = stack.ResolvePath(config.BlobPool.Datadir)
	}
	blobPool := blobpool.New(config.BlobPool, eth.blockchain, legacyPool.HasPendingAuth)

	eth.txPool, err = txpool.New(config.TxPool.PriceLimit, eth.blockchain, []txpool.SubPool{legacyPool, blobPool})
	if err != nil {
		return nil, err
	}

	if !config.TxPool.NoLocals {
		rejournal := config.TxPool.Rejournal
		if rejournal < time.Second {
			log.Warn("Sanitizing invalid txpool journal time", "provided", rejournal, "updated", time.Second)
			rejournal = time.Second
		}
		eth.localTxTracker = locals.New(config.TxPool.Journal, rejournal, eth.blockchain.Config(), eth.txPool)
		stack.RegisterLifecycle(eth.localTxTracker)
	}

	// Permit the downloader to use the trie cache allowance during fast sync
	cacheLimit := cacheConfig.TrieCleanLimit + cacheConfig.TrieDirtyLimit + cacheConfig.SnapshotLimit
	if eth.handler, err = newHandler(&handlerConfig{
		NodeID:         eth.p2pServer.Self().ID(),
		Database:       chainDb,
		Chain:          eth.blockchain,
		TxPool:         eth.txPool,
		Network:        networkID,
		Sync:           config.SyncMode,
		BloomCache:     uint64(cacheLimit),
		EventMux:       eth.eventMux,
		RequiredBlocks: config.RequiredBlocks,
	}); err != nil {
		return nil, err
	}

	eth.dropper = newDropper(eth.p2pServer.MaxDialedConns(), eth.p2pServer.MaxInboundConns())

	// Move APIBackend creation BEFORE miner creation
	eth.APIBackend = &EthAPIBackend{
		extRPCEnabled:       stack.Config().ExtRPCEnabled(),
		allowUnprotectedTxs: stack.Config().AllowUnprotectedTxs,
		eth:                 eth,
		gpo:                 nil,
		SimStore:            eth.simStore,
		IsIntentGuard:       eth.isIntentGuard,
		txSimulationPool:    eth.txSimulationPool,
	}

	// THEN create the miner (which now can access the APIBackend)
	eth.miner = miner.New(eth, &miner.Config{
		Etherbase:           config.Miner.Etherbase,
		PendingFeeRecipient: config.Miner.PendingFeeRecipient,
		ExtraData:           config.Miner.ExtraData,
		GasCeil:             config.Miner.GasCeil,
		GasPrice:            config.Miner.GasPrice,
		Recommit:            config.Miner.Recommit,
		ExternalRPC:         config.Miner.ExternalRPC,
	}, eth.engine, &FirewallAPIWrapper{api: ethapi.NewFirewallAPI(eth.APIBackend)})
	eth.miner.SetExtra(makeExtraData(config.Miner.ExtraData))
	eth.miner.SetPrioAddresses(config.TxPool.Locals)

	// Set the gas price oracle (which depends on APIBackend existing)
	if eth.APIBackend.allowUnprotectedTxs {
		log.Info("Unprotected transactions allowed")
	}
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, config.GPO, config.Miner.GasPrice)

	// Start the RPC service
	eth.netRPCService = ethapi.NewNetAPI(eth.p2pServer, networkID)

	// Register the backend on the node
	stack.RegisterAPIs(eth.APIs())
	stack.RegisterProtocols(eth.Protocols())
	stack.RegisterLifecycle(eth)

	// Successful startup; push a marker and check previous unclean shutdowns.
	eth.shutdownTracker.MarkStartup()

	return eth, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(gethversion.Major<<16 | gethversion.Minor<<8 | gethversion.Patch),
			"geth",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// APIs return the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Ethereum) APIs() []rpc.API {
	// Get base APIs but modify transaction handling for simulate mode
	apis := ethapi.GetAPIs(s.APIBackend)

	// If in simulate mode, we need to modify the transaction pool API
	if s.isIntentGuard {
		log.Info("Running in simulate mode - transaction interception enabled")
		// The transaction pool API will automatically detect simulate mode

	}

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "miner",
			Service:   NewMinerAPI(s),
		}, {
			Namespace: "eth",
			Service:   downloader.NewDownloaderAPI(s.handler.downloader, s.blockchain, s.eventMux),
		}, {
			Namespace: "admin",
			Service:   NewAdminAPI(s),
		}, {
			Namespace: "debug",
			Service:   NewDebugAPI(s),
		}, {
			Namespace: "net",
			Service:   s.netRPCService,
		}, {
			Namespace: "firewall",
			Service:   ethapi.NewFirewallAPI(s.APIBackend),
		},
	}...)
}

func (s *Ethereum) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Ethereum) Miner() *miner.Miner { return s.miner }

func (s *Ethereum) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *Ethereum) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *Ethereum) TxPool() *txpool.TxPool             { return s.txPool }
func (s *Ethereum) Engine() consensus.Engine           { return s.engine }
func (s *Ethereum) ChainDb() ethdb.Database            { return s.chainDb }
func (s *Ethereum) IsListening() bool                  { return true } // Always listening
func (s *Ethereum) Downloader() *downloader.Downloader { return s.handler.downloader }
func (s *Ethereum) Synced() bool                       { return s.handler.synced.Load() }
func (s *Ethereum) SetSynced()                         { s.handler.enableSyncedFeatures() }
func (s *Ethereum) ArchiveMode() bool                  { return s.config.NoPruning }

// Protocols returns all the currently configured
// network protocols to start.
func (s *Ethereum) Protocols() []p2p.Protocol {
	protos := eth.MakeProtocols((*ethHandler)(s.handler), s.networkID, s.discmix)
	if s.config.SnapshotCache > 0 {
		protos = append(protos, snap.MakeProtocols((*snapHandler)(s.handler))...)
	}
	return protos
}

// Start implements node.Lifecycle, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (s *Ethereum) Start() error {
	if err := s.setupDiscovery(); err != nil {
		return err
	}

	// Regularly update shutdown marker
	s.shutdownTracker.Start()

	// Start the networking layer
	s.handler.Start(s.p2pServer.MaxPeers)

	// Start the connection manager
	s.dropper.Start(s.p2pServer, func() bool { return !s.Synced() })

	// start log indexer
	s.filterMaps.Start()
	go s.updateFilterMapsHeads()

	return nil
}

func (s *Ethereum) newChainView(head *types.Header) *filtermaps.ChainView {
	if head == nil {
		return nil
	}
	return filtermaps.NewChainView(s.blockchain, head.Number.Uint64(), head.Hash())
}

func (s *Ethereum) updateFilterMapsHeads() {
	headEventCh := make(chan core.ChainEvent, 10)
	blockProcCh := make(chan bool, 10)
	sub := s.blockchain.SubscribeChainEvent(headEventCh)
	sub2 := s.blockchain.SubscribeBlockProcessingEvent(blockProcCh)
	defer func() {
		sub.Unsubscribe()
		sub2.Unsubscribe()
		for {
			select {
			case <-headEventCh:
			case <-blockProcCh:
			default:
				return
			}
		}
	}()

	var head *types.Header
	setHead := func(newHead *types.Header) {
		if newHead == nil {
			return
		}
		if head == nil || newHead.Hash() != head.Hash() {
			head = newHead
			chainView := s.newChainView(head)
			historyCutoff, _ := s.blockchain.HistoryPruningCutoff()
			var finalBlock uint64
			if fb := s.blockchain.CurrentFinalBlock(); fb != nil {
				finalBlock = fb.Number.Uint64()
			}
			s.filterMaps.SetTarget(chainView, historyCutoff, finalBlock)
		}
	}
	setHead(s.blockchain.CurrentBlock())

	for {
		select {
		case ev := <-headEventCh:
			setHead(ev.Header)
		case blockProc := <-blockProcCh:
			s.filterMaps.SetBlockProcessing(blockProc)
		case <-time.After(time.Second * 10):
			setHead(s.blockchain.CurrentBlock())
		case ch := <-s.closeFilterMaps:
			close(ch)
			return
		}
	}
}

func (s *Ethereum) setupDiscovery() error {
	eth.StartENRUpdater(s.blockchain, s.p2pServer.LocalNode())

	// Add eth nodes from DNS.
	dnsclient := dnsdisc.NewClient(dnsdisc.Config{})
	if len(s.config.EthDiscoveryURLs) > 0 {
		iter, err := dnsclient.NewIterator(s.config.EthDiscoveryURLs...)
		if err != nil {
			return err
		}
		s.discmix.AddSource(iter)
	}

	// Add snap nodes from DNS.
	if len(s.config.SnapDiscoveryURLs) > 0 {
		iter, err := dnsclient.NewIterator(s.config.SnapDiscoveryURLs...)
		if err != nil {
			return err
		}
		s.discmix.AddSource(iter)
	}

	// Add DHT nodes from discv5.
	if s.p2pServer.DiscoveryV5() != nil {
		filter := eth.NewNodeFilter(s.blockchain)
		iter := enode.Filter(s.p2pServer.DiscoveryV5().RandomNodes(), filter)
		s.discmix.AddSource(iter)
	}

	return nil
}

// Stop implements node.Lifecycle, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *Ethereum) Stop() error {
	// Stop all the peer-related stuff first.
	s.discmix.Close()
	s.dropper.Stop()
	s.handler.Stop()

	// Then stop everything else.
	ch := make(chan struct{})
	s.closeFilterMaps <- ch
	<-ch
	s.filterMaps.Stop()
	s.txPool.Close()
	s.blockchain.Stop()
	s.engine.Close()

	// Clean shutdown marker as the last thing before closing db
	s.shutdownTracker.Stop()

	s.chainDb.Close()
	s.eventMux.Stop()

	return nil
}

// SyncMode retrieves the current sync mode, either explicitly set, or derived
// from the chain status.
func (s *Ethereum) SyncMode() ethconfig.SyncMode {
	// If we're in snap sync mode, return that directly
	if s.handler.snapSync.Load() {
		return ethconfig.SnapSync
	}
	// We are probably in full sync, but we might have rewound to before the
	// snap sync pivot, check if we should re-enable snap sync.
	head := s.blockchain.CurrentBlock()
	if pivot := rawdb.ReadLastPivotNumber(s.chainDb); pivot != nil {
		if head.Number.Uint64() < *pivot {
			return ethconfig.SnapSync
		}
	}
	// We are in a full sync, but the associated head state is missing. To complete
	// the head state, forcefully rerun the snap sync. Note it doesn't mean the
	// persistent state is corrupted, just mismatch with the head block.
	if !s.blockchain.HasState(head.Root) {
		log.Info("Reenabled snap sync as chain is stateless")
		return ethconfig.SnapSync
	}
	// Nope, we're really full syncing
	return ethconfig.FullSync
}

func (s *Ethereum) EnableIntentGuardMode() {
	s.isIntentGuard = true
}
func (s *Ethereum) DisableIntentGuardMode() {
	s.isIntentGuard = false
}

func (e *Ethereum) SimChainStore() *state.SimulatedChainStore {
	return e.simStore
}

func (e *Ethereum) TxSimulationPool() interface{} {
	return e.txSimulationPool
}

func (b *EthAPIBackend) TxSimulationPool() *firewall.TxSimulationPool {
	return b.txSimulationPool
}

// PrivateTxPool methods for Intent Guard mode
func (s *Ethereum) PrivateTxPool() *PrivateTxPool {
	return s.privateTxPool
}

func (s *Ethereum) AddToPrivatePool(tx *types.Transaction) error {
	if s.privateTxPool == nil {
		return fmt.Errorf("private transaction pool not initialized")
	}
	log.Info("Pre-private-pool", "hash", tx.Hash().Hex(), "nonce", tx.Nonce(), "chainId", tx.ChainId())
	return s.privateTxPool.AddTransaction(tx)
}
