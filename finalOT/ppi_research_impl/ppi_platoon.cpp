/**
 * Private Prefix Intersection (PPI) prototype/benchmark implementation.
 *
 * Cryptographic OT layer:
 *   - OOS malicious 1-out-of-N random OT, instantiated by libOTe.
 *
 * Application layer implemented here:
 *   - trajectory commitments registered in an in-memory Smart Contract ledger;
 *   - stateful hash-chain payload generation;
 *   - prefix evaluation and threshold decision.
 *
 * The Smart Contract and local communication harness are intentionally modeled
 * as abstractions. The OT primitive is NOT simulated: all base OT, OOS
 * extension, active consistency checks, and OT key derivation are delegated to
 * libOTe's concrete OOS implementation.
 */

#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "libOTe/Tools/Coproto.h"
#include "ppi_oos_adapter.hpp"

namespace ppi {

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using Trajectory = std::vector<std::uint32_t>;

// Paper-aligned parameters: κ = 128 computational bits.
constexpr std::size_t K_BYTES = 16;        // κ bits
constexpr std::size_t HASH_BYTES = 32;     // 2κ-bit SHA-256 commitment
constexpr std::size_t TAG_BYTES = 16;      // κ-bit authentication tag
constexpr std::size_t WAYPOINT_BYTES = 4;  // uint32_t waypoint/symbol
constexpr std::uint32_t STAT_SEC = 40;
constexpr std::size_t PAYLOAD_BLOCK_BYTES =
    K_BYTES + WAYPOINT_BYTES + K_BYTES;
constexpr std::size_t MAX_HENC_BYTES = 64;

// -----------------------------------------------------------------------------
// Basic serialization / randomness / hashing
// -----------------------------------------------------------------------------

void append_u32_be(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<Byte>((value >> 24) & 0xff));
    out.push_back(static_cast<Byte>((value >> 16) & 0xff));
    out.push_back(static_cast<Byte>((value >> 8) & 0xff));
    out.push_back(static_cast<Byte>(value & 0xff));
}

std::uint32_t read_u32_be(const Byte* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

Bytes random_bytes(std::size_t length) {
    Bytes result(length);
    if (length == 0) return result;
    if (RAND_bytes(result.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed");
    }
    return result;
}

Bytes sha256(const Bytes& data) {
    Bytes result(EVP_MAX_MD_SIZE);
    unsigned int result_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    const bool ok =
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, result.data(), &result_len) == 1;

    EVP_MD_CTX_free(ctx);

    if (!ok) throw std::runtime_error("SHA-256 operation failed");
    result.resize(result_len);
    return result;
}

Bytes domain_hash(Byte domain, const Bytes& message) {
    Bytes input;
    input.reserve(1 + message.size());
    input.push_back(domain);
    input.insert(input.end(), message.begin(), message.end());
    return sha256(input);
}

bool ct_equal(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

Bytes xor_bytes(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("xor_bytes size mismatch");
    }
    Bytes result(a.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        result[i] = static_cast<Byte>(a[i] ^ b[i]);
    }
    return result;
}

// -----------------------------------------------------------------------------
// Paper primitives H_com, H_tag, H_enc.
// Domain separation is explicit so the three hash functions cannot share an
// accidental input domain.
// -----------------------------------------------------------------------------

Bytes H_com(std::uint32_t k,
            std::uint32_t waypoint,
            const Bytes& randomness) {
    Bytes input;
    input.reserve(8 + randomness.size());
    append_u32_be(input, k);
    append_u32_be(input, waypoint);
    input.insert(input.end(), randomness.begin(), randomness.end());
    return domain_hash(0x01, input); // 256-bit output
}

Bytes H_tag(std::uint32_t k, const Bytes& state) {
    Bytes input;
    input.reserve(4 + state.size());
    append_u32_be(input, k);
    input.insert(input.end(), state.begin(), state.end());
    const Bytes digest = domain_hash(0x02, input);
    return Bytes(digest.begin(), digest.begin() + TAG_BYTES);
}

Bytes H_enc(std::uint32_t k,
            const Bytes& previous_state,
            const Bytes& ot_key,
            std::size_t output_bytes) {
    if (output_bytes > MAX_HENC_BYTES) {
        throw std::invalid_argument("H_enc output too large");
    }

    Bytes output;
    output.reserve(output_bytes);

    for (std::uint32_t counter = 0; output.size() < output_bytes; ++counter) {
        Bytes input;
        input.reserve(4 + 4 + previous_state.size() + ot_key.size());
        append_u32_be(input, counter);
        append_u32_be(input, k);
        input.insert(input.end(), previous_state.begin(), previous_state.end());
        input.insert(input.end(), ot_key.begin(), ot_key.end());

        const Bytes digest = domain_hash(0x03, input);
        const std::size_t take =
            std::min<std::size_t>(digest.size(), output_bytes - output.size());
        output.insert(output.end(), digest.begin(), digest.begin() + take);
    }

    return output;
}

// -----------------------------------------------------------------------------
// Smart Contract abstraction.
// It is a local immutable/public ledger model, not a cryptographic black box.
// -----------------------------------------------------------------------------

class SmartContractLedger {
public:
    void register_commitment(const std::string& session_id,
                             const std::vector<Bytes>& commitments) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (entries_.contains(session_id)) {
            throw std::runtime_error("duplicate session commitment");
        }
        entries_.emplace(session_id, Entry{commitments, false});
        cv_.notify_all();
    }

    std::vector<Bytes> begin_single_use_evaluation(
        const std::string& session_id) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [&] { return entries_.contains(session_id); });

        Entry& entry = entries_.at(session_id);
        if (entry.used) {
            throw std::runtime_error(
                "trajectory commitment already evaluated for this session");
        }

        entry.used = true;
        return entry.commitments;
    }

private:
    struct Entry {
        std::vector<Bytes> commitments;
        bool used;
    };

    std::mutex mutex_;
    std::condition_variable cv_;
    std::unordered_map<std::string, Entry> entries_;
};

// -----------------------------------------------------------------------------
// Application channel abstraction for the aggregate payload.
// The cryptographic OT traffic itself uses libOTe/coproto directly.
// -----------------------------------------------------------------------------

struct AggregatePayload {
    Bytes s0;
    std::vector<Bytes> payload;
    std::vector<Bytes> tags;
};

class PayloadChannel {
public:
    void publish(AggregatePayload value) {
        std::lock_guard<std::mutex> lock(mutex_);
        payload_ = std::move(value);
        ready_ = true;
        cv_.notify_all();
    }

    AggregatePayload receive() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [&] { return ready_; });
        return payload_;
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    bool ready_ = false;
    AggregatePayload payload_;
};

// -----------------------------------------------------------------------------
// OOS wrapper.
// -----------------------------------------------------------------------------

class OosRandomOT {
public:
    using Sender = ppi_oos::Sender;
    using Receiver = ppi_oos::Receiver;

    static std::size_t input_bits_for_alphabet(std::uint32_t sigma_size) {
        if (sigma_size < 2) {
            throw std::invalid_argument("alphabet must contain at least 2 symbols");
        }
        std::size_t bits = 0;
        std::uint32_t domain = 1;
        while (domain < sigma_size) {
            ++bits;
            domain <<= 1;
        }
        return bits;
    }

    static void run_sender(Sender& sender,
                           std::size_t n,
                           std::uint32_t sigma_size,
                           const Trajectory& leader_path,
                           std::vector<std::vector<Bytes>>& sender_keys,
                           coproto::Socket& channel) {
        const std::size_t input_bits = input_bits_for_alphabet(sigma_size);
        sender.configure(true, STAT_SEC, input_bits);

        osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
        coproto::sync_wait(sender.genBaseOts(prng, channel));
        coproto::sync_wait(sender.init(n, prng, channel));

        // Receiver must first send all OOS corrections. The sender blocks here
        // until those corrections have been received.
        coproto::sync_wait(sender.recvCorrection(channel, n));

        sender_keys.assign(
            n, std::vector<Bytes>(sigma_size, Bytes(K_BYTES)));

        for (std::size_t i = 0; i < n; ++i) {
            for (std::uint32_t choice = 0; choice < sigma_size; ++choice) {
                sender.encode(
                    static_cast<osuCrypto::u64>(i),
                    &choice,
                    sender_keys[i][choice].data(),
                    static_cast<osuCrypto::u64>(K_BYTES));
            }
        }

        // libOTe's malicious NCO implementation performs its active check here.
        // The seed is local randomness supplied to the library; the actual check
        // communication is carried by `channel`.
        const osuCrypto::block check_seed = osuCrypto::sysRandomSeed();
        coproto::sync_wait(sender.check(channel, check_seed));

        (void)leader_path; // Used later by the PPI payload construction.
    }

    static void run_receiver(Receiver& receiver,
                             std::size_t n,
                             std::uint32_t sigma_size,
                             const Trajectory& applicant_path,
                             std::vector<Bytes>& receiver_keys,
                             coproto::Socket& channel) {
        const std::size_t input_bits = input_bits_for_alphabet(sigma_size);
        receiver.configure(true, STAT_SEC, input_bits);

        osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
        coproto::sync_wait(receiver.genBaseOts(prng, channel));
        coproto::sync_wait(receiver.init(n, prng, channel));

        receiver_keys.assign(n, Bytes(K_BYTES));

        // Generate all receiver-side OOS choices first. encode() records the
        // correction data internally; sendCorrection() sends it to the sender.
        for (std::size_t i = 0; i < n; ++i) {
            const std::uint32_t choice = applicant_path[i];
            if (choice >= sigma_size) {
                throw std::invalid_argument("applicant symbol outside alphabet");
            }

            receiver.encode(
                static_cast<osuCrypto::u64>(i),
                &choice,
                receiver_keys[i].data(),
                static_cast<osuCrypto::u64>(K_BYTES));
        }

        coproto::sync_wait(receiver.sendCorrection(channel, n));

        // The receiver must execute the same active OOS check phase.
        const osuCrypto::block check_seed = osuCrypto::sysRandomSeed();
        coproto::sync_wait(receiver.check(channel, check_seed));
    }
};

// -----------------------------------------------------------------------------
// PPI sender state and payload construction.
// -----------------------------------------------------------------------------

struct LeaderSecrets {
    std::vector<Bytes> randomness;
};

struct PPIResult {
    std::size_t prefix_length = 0;
    bool eligible = false;
};

LeaderSecrets commit_trajectory(const std::string& session_id,
                                const Trajectory& leader_path,
                                SmartContractLedger& sc) {
    LeaderSecrets secrets;
    secrets.randomness.resize(leader_path.size());

    std::vector<Bytes> commitments(leader_path.size());

    for (std::size_t i = 0; i < leader_path.size(); ++i) {
        secrets.randomness[i] = random_bytes(K_BYTES);
        commitments[i] = H_com(
            static_cast<std::uint32_t>(i + 1),
            leader_path[i],
            secrets.randomness[i]);
    }

    // The commitment vector is registered at the SC, never sent directly to TA.
    sc.register_commitment(session_id, commitments);
    return secrets;
}

AggregatePayload build_payload(
    const Trajectory& leader_path,
    const LeaderSecrets& secrets,
    const std::vector<std::vector<Bytes>>& sender_keys) {
    const std::size_t n = leader_path.size();
    AggregatePayload message;
    message.s0 = random_bytes(K_BYTES);
    message.payload.resize(n);
    message.tags.resize(n);

    Bytes previous_state = message.s0;

    for (std::size_t i = 0; i < n; ++i) {
        const std::uint32_t k = static_cast<std::uint32_t>(i + 1);
        const Bytes& ot_key = sender_keys[i][leader_path[i]];
        const Bytes current_state = random_bytes(K_BYTES);

        const Bytes mask = H_enc(
            k, previous_state, ot_key, PAYLOAD_BLOCK_BYTES);

        Bytes cleartext;
        cleartext.reserve(PAYLOAD_BLOCK_BYTES);
        cleartext.insert(cleartext.end(), current_state.begin(), current_state.end());
        append_u32_be(cleartext, leader_path[i]);
        cleartext.insert(
            cleartext.end(),
            secrets.randomness[i].begin(),
            secrets.randomness[i].end());

        message.payload[i] = xor_bytes(cleartext, mask);
        message.tags[i] = H_tag(k, current_state);
        previous_state = current_state;
    }

    return message;
}

PPIResult evaluate_prefix(
    const Trajectory& applicant_path,
    const std::vector<Bytes>& commitments,
    const AggregatePayload& message,
    const std::vector<Bytes>& receiver_keys,
    std::uint32_t tau_min) {
    const std::size_t n = applicant_path.size();

    if (commitments.size() != n ||
        message.payload.size() != n ||
        message.tags.size() != n ||
        receiver_keys.size() != n) {
        throw std::invalid_argument("PPI vector length mismatch");
    }

    Bytes previous_state = message.s0;
    std::size_t prefix_length = 0;

    for (std::size_t i = 0; i < n; ++i) {
        const std::uint32_t k = static_cast<std::uint32_t>(i + 1);
        const Bytes mask = H_enc(
            k, previous_state, receiver_keys[i], PAYLOAD_BLOCK_BYTES);
        const Bytes cleartext = xor_bytes(message.payload[i], mask);

        const Bytes recovered_state(
            cleartext.begin(), cleartext.begin() + K_BYTES);
        const std::uint32_t recovered_symbol = read_u32_be(
            cleartext.data() + K_BYTES);
        const Bytes recovered_randomness(
            cleartext.begin() + K_BYTES + WAYPOINT_BYTES,
            cleartext.end());

        const bool tag_ok = ct_equal(
            message.tags[i], H_tag(k, recovered_state));
        const bool commitment_ok = ct_equal(
            commitments[i],
            H_com(k, recovered_symbol, recovered_randomness));
        const bool equality_ok = recovered_symbol == applicant_path[i];

        if (!(tag_ok && commitment_ok && equality_ok)) {
            break;
        }

        previous_state = recovered_state;
        prefix_length = i + 1;
    }

    return PPIResult{
        prefix_length,
        prefix_length >= tau_min
    };
}

// -----------------------------------------------------------------------------
// End-to-end PPI experiment harness (PPI only; no TGDH).
// -----------------------------------------------------------------------------

void sender_job(const std::string& session_id,
                const Trajectory& leader_path,
                std::uint32_t sigma_size,
                SmartContractLedger& sc,
                PayloadChannel& payload_channel,
                coproto::Socket& ot_channel) {
    try {
        std::cout << "[Leader] Phase 1: register trajectory commitments at SC\n";
        const LeaderSecrets secrets = commit_trajectory(session_id, leader_path, sc);

        std::vector<std::vector<Bytes>> sender_keys;
        OosRandomOT::Sender sender;

        std::cout << "[Leader] Phase 2: execute malicious OOS OT extension\n";
        OosRandomOT::run_sender(
            sender,
            leader_path.size(),
            sigma_size,
            leader_path,
            sender_keys,
            ot_channel);

        std::cout << "[Leader] Phase 3: build aggregate PPI payload\n";
        AggregatePayload message =
            build_payload(leader_path, secrets, sender_keys);
        payload_channel.publish(std::move(message));

        std::cout << "[Leader] Payload published to the communication channel.\n";
    } catch (const std::exception& e) {
        std::cerr << "[Leader] ERROR: " << e.what() << '\n';
        throw;
    }
}

void receiver_job(const std::string& session_id,
                  const Trajectory& applicant_path,
                  std::uint32_t sigma_size,
                  std::uint32_t tau_min,
                  SmartContractLedger& sc,
                  PayloadChannel& payload_channel,
                  coproto::Socket& ot_channel) {
    try {
        std::cout << "[Applicant] Phase 1: read commitments from SC\n";
        const std::vector<Bytes> commitments =
            sc.begin_single_use_evaluation(session_id);

        std::vector<Bytes> receiver_keys;
        OosRandomOT::Receiver receiver;

        std::cout << "[Applicant] Phase 2: execute malicious OOS OT extension\n";
        OosRandomOT::run_receiver(
            receiver,
            applicant_path.size(),
            sigma_size,
            applicant_path,
            receiver_keys,
            ot_channel);

        std::cout << "[Applicant] Phase 3: evaluate private prefix\n";
        const AggregatePayload message = payload_channel.receive();
        const PPIResult result = evaluate_prefix(
            applicant_path,
            commitments,
            message,
            receiver_keys,
            tau_min);

        std::cout << "[Applicant] Prefix length = " << result.prefix_length << '\n';
        std::cout << "[Applicant] Eligibility = "
                  << (result.eligible ? "ACCEPT" : "REJECT") << '\n';
    } catch (const std::exception& e) {
        std::cerr << "[Applicant] ERROR: " << e.what() << '\n';
        throw;
    }
}

Trajectory make_leader_trajectory(std::size_t n,
                                  std::uint32_t sigma_size) {
    Trajectory path(n);
    for (std::size_t i = 0; i < n; ++i) {
        path[i] = static_cast<std::uint32_t>(i % sigma_size);
    }
    return path;
}

Trajectory make_applicant_trajectory(const Trajectory& leader,
                                     std::size_t divergence,
                                     std::uint32_t sigma_size) {
    Trajectory path = leader;
    if (divergence < path.size()) {
        path[divergence] = (path[divergence] + 1) % sigma_size;
        // All entries after the divergence remain equal to the leader. This is
        // intentional: it tests strict prefix privacy rather than ordinary PSI.
    }
    return path;
}

} // namespace ppi

int main(int argc, char** argv) {
    try {
        std::size_t n = 10;
        std::uint32_t sigma_size = 5;
        std::uint32_t tau_min = 4;
        std::size_t intentional_diverge = 6;

        if (argc == 5) {
            n = std::stoull(argv[1]);
            sigma_size = static_cast<std::uint32_t>(std::stoul(argv[2]));
            tau_min = static_cast<std::uint32_t>(std::stoul(argv[3]));
            intentional_diverge = std::stoull(argv[4]);
        } else if (argc != 1) {
            std::cerr
                << "Usage: " << argv[0]
                << " [n sigma_size tau_min divergence_index]\n";
            return EXIT_FAILURE;
        }

        if (n == 0) throw std::invalid_argument("n must be positive");
        if (sigma_size < 2) {
            throw std::invalid_argument("sigma_size must be at least 2");
        }
        if (tau_min > n) {
            throw std::invalid_argument("tau_min must not exceed n");
        }
        if (intentional_diverge > n) {
            throw std::invalid_argument("divergence_index must be <= n");
        }

        const ppi::Trajectory leader =
            ppi::make_leader_trajectory(n, sigma_size);
        const ppi::Trajectory applicant =
            ppi::make_applicant_trajectory(
                leader, intentional_diverge, sigma_size);

        // Actual libOTe/coproto communication channel for OOS.
        auto ot_sockets = coproto::LocalAsyncSocket::makePair();

        ppi::SmartContractLedger sc;
        ppi::PayloadChannel payload_channel;
        const std::string session_id = "ppi-session-001";

        std::exception_ptr sender_error;
        std::exception_ptr receiver_error;

        std::thread sender_thread([&] {
            try {
                ppi::sender_job(
                    session_id,
                    leader,
                    sigma_size,
                    sc,
                    payload_channel,
                    ot_sockets[0]);
            } catch (...) {
                sender_error = std::current_exception();
            }
        });

        std::thread receiver_thread([&] {
            try {
                ppi::receiver_job(
                    session_id,
                    applicant,
                    sigma_size,
                    tau_min,
                    sc,
                    payload_channel,
                    ot_sockets[1]);
            } catch (...) {
                receiver_error = std::current_exception();
            }
        });

        sender_thread.join();
        receiver_thread.join();

        if (sender_error) std::rethrow_exception(sender_error);
        if (receiver_error) std::rethrow_exception(receiver_error);

        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
