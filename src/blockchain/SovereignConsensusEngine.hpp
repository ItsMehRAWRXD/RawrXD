// Phase D.17 Batch 2/5: Consensus Engine
// Blockchain consensus mechanisms (PoW, PoS, BFT)
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Blockchain {

// Forward declarations
struct Block;
struct Validator;
struct ConsensusState;

// ============================================================================
// Consensus Types
// ============================================================================

enum class ConsensusAlgorithm {
    PROOF_OF_WORK = 0,
    PROOF_OF_STAKE = 1,
    DELEGATED_POS = 2,
    PRACTICAL_BFT = 3,
    HOTSTUFF = 4,
    TENDERMINT = 5,
    RAFT = 6,
    SOVERIGN_BFT = 7
};

enum class ConsensusState {
    PROPOSE = 0,
    PREVOTE = 1,
    PRECOMMIT = 2,
    COMMIT = 3,
    FINALIZE = 4
};

enum class ValidatorStatus {
    INACTIVE = 0,
    ACTIVE = 1,
    JAILED = 2,
    TOMBSTONED = 3
};

struct Block {
    uint64_t number;
    std::vector<uint8_t> hash;
    std::vector<uint8_t> parent_hash;
    std::vector<uint8_t> state_root;
    std::vector<uint8_t> tx_root;
    std::vector<uint8_t> receipt_root;
    std::vector<uint8_t> extra_data;
    uint64_t timestamp;
    uint64_t gas_used;
    uint64_t gas_limit;
    std::vector<Transaction> transactions;
    std::vector<uint8_t> validator_signature;
    std::vector<uint8_t> seal;
};

struct Validator {
    std::string address;
    std::vector<uint8_t> public_key;
    uint64_t voting_power;
    uint64_t stake_amount;
    ValidatorStatus status;
    uint64_t joined_at;
    uint64_t last_active;
    std::string moniker;
    std::string website;
    std::string identity;
    std::map<std::string, std::any> metadata;
};

struct Vote {
    ConsensusState type;
    uint64_t height;
    uint32_t round;
    std::vector<uint8_t> block_hash;
    std::string validator_address;
    std::vector<uint8_t> signature;
    uint64_t timestamp;
};

// ============================================================================
// Proof of Work Engine
// ============================================================================

class PoWEngine {
public:
    struct Config {
        uint64_t block_time_target = 15;  // seconds
        uint64_t difficulty_adjustment_interval = 2016;  // blocks
        uint64_t min_difficulty = 1;
        uint64_t max_difficulty = std::numeric_limits<uint64_t>::max();
        std::string hash_algorithm = "ethash";
    };
    
    struct MiningResult {
        bool success;
        uint64_t nonce;
        std::vector<uint8_t> mix_hash;
        uint64_t attempts;
        std::chrono::milliseconds duration;
    };
    
    explicit PoWEngine(const Config& config);
    ~PoWEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Mining
    MiningResult MineBlock(const Block& block, uint64_t timeout_ms);
    bool VerifyPoW(const Block& block);
    
    // Difficulty adjustment
    uint64_t CalculateDifficulty(const std::vector<Block>& recent_blocks);
    uint64_t GetCurrentDifficulty() const;
    
    // Hash verification
    std::vector<uint8_t> ComputeHash(const Block& block, uint64_t nonce);
    bool CheckHashDifficulty(const std::vector<uint8_t>& hash, uint64_t difficulty);
    
private:
    Config config_;
    uint64_t current_difficulty_;
    mutable std::mutex difficulty_mutex_;
    
    std::vector<uint8_t> EthashHash(const Block& block, uint64_t nonce);
    std::vector<uint8_t> DoubleSHA256(const Block& block, uint64_t nonce);
};

// ============================================================================
// Proof of Stake Engine
// ============================================================================

class PoSEngine {
public:
    struct Config {
        uint64_t min_stake_amount = 32000000;  // 32 tokens
        uint64_t block_time = 12;  // seconds
        uint64_t epoch_length = 32;  // slots
        uint64_t slash_fraction = 4;  // 1/4 of stake slashed
        uint64_t unbonding_period = 1814400;  // 21 days in seconds
    };
    
    struct Epoch {
        uint64_t number;
        uint64_t start_slot;
        uint64_t end_slot;
        std::vector<std::string> validator_set;
        std::vector<uint8_t> seed;
        std::map<std::string, uint64_t> proposer_schedule;
    };
    
    explicit PoSEngine(const Config& config);
    ~PoSEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Validator management
    bool RegisterValidator(const Validator& validator);
    bool UnregisterValidator(const std::string& address);
    bool UpdateStake(const std::string& address, uint64_t new_stake);
    bool SlashValidator(const std::string& address, const std::string& reason);
    
    // Block production
    std::string SelectProposer(uint64_t slot);
    bool ValidateBlockProducer(const Block& block, uint64_t slot);
    
    // Epoch management
    Epoch ComputeNextEpoch(const std::vector<Block>& previous_blocks);
    bool IsEpochTransition(uint64_t slot);
    
    // Rewards
    uint64_t CalculateBlockReward(uint64_t slot);
    uint64_t CalculateAttestationReward(const Vote& vote);
    
private:
    Config config_;
    std::map<std::string, Validator> validators_;
    mutable std::mutex validators_mutex_;
    Epoch current_epoch_;
    
    std::vector<std::string> ShuffleValidators(const std::vector<uint8_t>& seed);
    uint64_t GetTotalStake() const;
};

// ============================================================================
// BFT Consensus Engine
// ============================================================================

class BFTEngine {
public:
    struct Config {
        uint32_t max_validators = 100;
        uint64_t block_time = 3;  // seconds
        uint32_t max_block_size = 22020096;  // 21MB
        uint64_t proposal_timeout = 3000;  // ms
        uint64_t prevote_timeout = 1000;   // ms
        uint64_t precommit_timeout = 1000; // ms
    };
    
    struct ConsensusRound {
        uint64_t height;
        uint32_t round;
        ConsensusState state;
        std::optional<Block> proposed_block;
        std::map<std::string, Vote> prevotes;
        std::map<std::string, Vote> precommits;
        uint64_t start_time;
    };
    
    explicit BFTEngine(const Config& config);
    ~BFTEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Consensus lifecycle
    bool StartRound(uint64_t height, uint32_t round);
    bool ProposeBlock(const Block& block);
    bool PrevVote(const std::vector<uint8_t>& block_hash);
    bool Precommit(const std::vector<uint8_t>& block_hash);
    bool CommitBlock();
    
    // Vote handling
    bool ReceiveVote(const Vote& vote);
    bool HasQuorumPrevotes(const std::vector<uint8_t>& block_hash);
    bool HasQuorumPrecommits(const std::vector<uint8_t>& block_hash);
    
    // State queries
    ConsensusState GetCurrentState() const;
    ConsensusRound GetCurrentRound() const;
    bool IsProposer(const std::string& address) const;
    
    // Timeout handling
    void OnProposalTimeout();
    void OnPrevoteTimeout();
    void OnPrecommitTimeout();
    
private:
    Config config_;
    ConsensusRound current_round_;
    std::vector<Validator> validators_;
    mutable std::mutex consensus_mutex_;
    
    uint64_t GetVotingPower(const std::string& address) const;
    uint64_t GetTotalVotingPower() const;
    uint64_t GetQuorum() const;
    void AdvanceRound();
};

// ============================================================================
// HotStuff Consensus
// ============================================================================

class HotStuffEngine {
public:
    struct Config {
        uint32_t max_validators = 100;
        uint64_t block_delay = 1000;  // ms
        uint64_t pacemaker_timeout = 4000;  // ms
        bool responsive_mode = true;
    };
    
    struct QuorumCertificate {
        std::vector<uint8_t> block_hash;
        uint64_t view_number;
        std::map<std::string, std::vector<uint8_t>> signatures;
        uint64_t timestamp;
    };
    
    struct HotStuffBlock {
        Block block;
        QuorumCertificate justify;
        uint64_t view_number;
    };
    
    explicit HotStuffEngine(const Config& config);
    ~HotStuffEngine();
    
    bool Initialize();
    void Shutdown();
    
    // HotStuff protocol
    bool Propose(const HotStuffBlock& block);
    bool Vote(const std::vector<uint8_t>& block_hash, uint64_t view);
    bool NewView(const QuorumCertificate& high_qc);
    
    // Pacemaker
    void OnBeat();
    void OnReceiveNewView(const QuorumCertificate& qc);
    void OnNextSyncView();
    
    // QC handling
    bool VerifyQC(const QuorumCertificate& qc);
    bool CreateQC(const std::vector<Vote>& votes);
    
    // Chained HotStuff
    bool UpdatePreferredBlock(const std::vector<uint8_t>& block_hash);
    bool CommitChain(const std::vector<uint8_t>& block_hash);
    
private:
    Config config_;
    uint64_t current_view_;
    std::map<uint64_t, HotStuffBlock> blocks_;
    std::map<uint64_t, QuorumCertificate> qcs_;
    mutable std::mutex hotstuff_mutex_;
    
    std::string GetLeader(uint64_t view);
    bool IsLeader(const std::string& address, uint64_t view);
};

// ============================================================================
// Consensus Manager
// ============================================================================

class ConsensusManager {
public:
    struct Config {
        ConsensusAlgorithm algorithm = ConsensusAlgorithm::SOVERIGN_BFT;
        PoWEngine::Config pow;
        PoSEngine::Config pos;
        BFTEngine::Config bft;
        HotStuffEngine::Config hotstuff;
    };
    
    explicit ConsensusManager(const Config& config);
    ~ConsensusManager();
    
    bool Initialize();
    void Shutdown();
    
    // Algorithm selection
    void SetAlgorithm(ConsensusAlgorithm algorithm);
    ConsensusAlgorithm GetAlgorithm() const;
    
    // Block finalization
    bool FinalizeBlock(Block& block);
    bool ValidateBlock(const Block& block);
    bool IsBlockFinalized(const std::vector<uint8_t>& block_hash);
    
    // Validator management
    bool AddValidator(const Validator& validator);
    bool RemoveValidator(const std::string& address);
    std::vector<Validator> GetValidators() const;
    
    // Fork choice
    std::vector<uint8_t> GetHeadBlock() const;
    std::vector<std::vector<uint8_t>> GetForks() const;
    bool ReorganizeChain(const std::vector<uint8_t>& new_head);
    
    // Stats
    struct ConsensusStats {
        uint64_t finalized_blocks;
        uint64_t average_block_time;
        uint64_t last_finalized_height;
        uint32_t active_validators;
        uint64_t total_voting_power;
    };
    ConsensusStats GetStats() const;
    
private:
    Config config_;
    ConsensusAlgorithm current_algorithm_;
    mutable std::mutex manager_mutex_;
    
    std::unique_ptr<PoWEngine> pow_engine_;
    std::unique_ptr<PoSEngine> pos_engine_;
    std::unique_ptr<BFTEngine> bft_engine_;
    std::unique_ptr<HotStuffEngine> hotstuff_engine_;
    
    std::map<std::vector<uint8_t>, Block> block_tree_;
    std::vector<uint8_t> finalized_head_;
};

// ============================================================================
// Consensus Runtime
// ============================================================================

class ConsensusRuntime {
public:
    struct Config {
        ConsensusManager::Config manager;
    };
    
    explicit ConsensusRuntime(const Config& config);
    ~ConsensusRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    ConsensusManager* GetManager();
    PoWEngine* GetPoW();
    PoSEngine* GetPoS();
    BFTEngine* GetBFT();
    HotStuffEngine* GetHotStuff();
    
    // High-level API
    bool StartConsensus();
    bool StopConsensus();
    bool SubmitBlock(const Block& block);
    bool SubmitTransaction(const Transaction& tx);
    
    Block GetLatestBlock() const;
    uint64_t GetBlockHeight() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ConsensusManager> manager_;
};

} // namespace Blockchain
} // namespace Sovereign
