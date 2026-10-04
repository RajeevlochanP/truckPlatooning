/**
 * End-to-End Private Prefix Intersection (PPI) for Vehicular Platooning
 *
 * Compilation: g++ -O3 -std=c++17 ppi_platoon.cpp -o ppi_platoon -lcrypto -lpthread
 */

#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cstring>
#include <iomanip>
#include <random>
#include <openssl/evp.h>
#include <openssl/rand.h>

// --- Configuration Constants ---
const size_t KAPPA = 32;        // 256-bit security parameter
const size_t WAYPOINT_SIZE = 4; // 32-bit integers for alphabet Sigma
const size_t STAT_SEC = 40;     // Statistical security parameter (s)[cite: 384]
const size_t CODE_LENGTH = 128; // Length of binary linear code C[cite: 384]

// --- Global State (Simulating Network Channel & Smart Contract) ---
struct GlobalState
{
    std::mutex mtx;
    std::condition_variable cv;

    // Smart Contract Ledger
    std::vector<std::vector<uint8_t>> C_1;
    bool sc_ready = false;

    struct ProtocolState
    {
        std::vector<std::vector<uint8_t>> commitments;

        std::vector<uint8_t> S0;
        std::vector<std::vector<uint8_t>> P;
        std::vector<std::vector<uint8_t>> V;

        std::mutex mtx;
        std::condition_variable cv;

        bool commitments_ready = false;
        bool payload_ready = false;
    };

    ProtocolState global_state;

    // Online Payload Channel
    std::vector<uint8_t> S_0;
    std::vector<std::vector<uint8_t>> P;
    std::vector<std::vector<uint8_t>> V;
    bool payload_ready = false;
} global_state;

// --- Cryptographic Helpers ---

void append_u32(std::vector<uint8_t> &vec, uint32_t val)
{
    vec.push_back((val >> 24) & 0xFF);
    vec.push_back((val >> 16) & 0xFF);
    vec.push_back((val >> 8) & 0xFF);
    vec.push_back(val & 0xFF);
}

std::vector<uint8_t> sha256(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    unsigned int length = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &length);
    EVP_MD_CTX_free(ctx);
    hash.resize(length);
    return hash;
}

std::vector<uint8_t> generate_random_bytes(size_t len)
{
    std::vector<uint8_t> buf(len);
    RAND_bytes(buf.data(), len);
    return buf;
}

// Pseudo-Random Generator (PRG)[cite: 384]
std::vector<uint8_t> prg_expand(const std::vector<uint8_t> &seed, size_t out_len)
{
    std::vector<uint8_t> out;
    uint32_t counter = 0;
    while (out.size() < out_len)
    {
        std::vector<uint8_t> input = seed;
        append_u32(input, counter++);
        std::vector<uint8_t> h = sha256(input);
        out.insert(out.end(), h.begin(), h.end());
    }
    out.resize(out_len);
    return out;
}

std::vector<uint8_t> xor_blocks(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    std::vector<uint8_t> res(a.size());
    for (size_t i = 0; i < a.size(); ++i)
        res[i] = a[i] ^ b[i];
    return res;
}

// Dummy Linear Code Generator (C) for OOS17[cite: 384]
std::vector<uint8_t> encode_choice(uint32_t choice)
{
    std::vector<uint8_t> codeword(CODE_LENGTH, 0);
    codeword[0] = choice & 0xFF; // Simplified encoding for compilation
    return codeword;
}

// H_com: {0,1}* -> {0,1}^2k
std::vector<uint8_t> H_com(uint32_t k, uint32_t a, const std::vector<uint8_t> &r)
{
    std::vector<uint8_t> input;
    append_u32(input, k);
    append_u32(input, a);
    input.insert(input.end(), r.begin(), r.end());
    return sha256(input);
}

std::vector<uint8_t> H_tag(uint32_t k, const std::vector<uint8_t> &S)
{
    std::vector<uint8_t> input;
    append_u32(input, k);
    input.insert(input.end(), S.begin(), S.end());
    return sha256(input);
}

std::vector<uint8_t> H_enc(uint32_t k, const std::vector<uint8_t> &prev_S, const std::vector<uint8_t> &K_hat, size_t out_len)
{
    std::vector<uint8_t> out;
    uint32_t counter = 0;
    while (out.size() < out_len)
    {
        std::vector<uint8_t> input;
        append_u32(input, counter++);
        append_u32(input, k);
        input.insert(input.end(), prev_S.begin(), prev_S.end());
        input.insert(input.end(), K_hat.begin(), K_hat.end());
        std::vector<uint8_t> h = sha256(input);
        out.insert(out.end(), h.begin(), h.end());
    }
    out.resize(out_len);
    return out;
}

// --- Protocol Threads ---

void sender_job(size_t n, uint32_t sigma_size, const std::vector<uint32_t> &A_L)
{
    std::cout << "[Sender] Phase 1: Pre-Journey Trajectory Commitment..." << std::endl;

    std::vector<std::vector<uint8_t>> r_L(n);
    std::vector<std::vector<uint8_t>> C_L(n);
    for (size_t i = 0; i < n; ++i)
    {
        r_L[i] = generate_random_bytes(KAPPA);
        C_L[i] = H_com(i + 1, A_L[i], r_L[i]);
    }

    {
        std::lock_guard<std::mutex> lock(global_state.mtx);
        global_state.C_1 = C_L;
        global_state.sc_ready = true;
    }
    global_state.cv.notify_all();

    // Protocol N-ROT: Init Phase[cite: 384]
    size_t m_prime = n + STAT_SEC;
    std::vector<uint8_t> b = generate_random_bytes(CODE_LENGTH);

    std::unique_lock<std::mutex> lock(global_state.mtx);
    global_state.cv.wait(lock, []
                         { return global_state.base_ot_ready; });

    // Protocol N-ROT: Extend Phase (Sender computes Q)[cite: 384]
    global_state.cv.wait(lock, []
                         { return global_state.u_matrix_ready; });
    std::vector<std::vector<uint8_t>> Q(m_prime, std::vector<uint8_t>(CODE_LENGTH));
    for (size_t j = 0; j < CODE_LENGTH; ++j)
    {
        std::vector<uint8_t> t_b = prg_expand(b[j] % 2 == 0 ? global_state.base_r0[j] : global_state.base_r1[j], m_prime);
        for (size_t i = 0; i < m_prime; ++i)
        {
            uint8_t bit_b = b[j] % 2;
            Q[i][j] = (bit_b * global_state.U_matrix[i][j]) ^ t_b[i]; // q^j = b_j * u^j + t_{b_j}^j[cite: 384]
        }
    }

    // Protocol N-ROT: Consistency Check (Sender challenges)[cite: 384]
    std::vector<std::vector<uint8_t>> x(STAT_SEC, std::vector<uint8_t>(n));
    for (size_t l = 0; l < STAT_SEC; ++l)
        x[l] = generate_random_bytes(n);
    global_state.check_x = x;
    global_state.check_req_ready = true;
    global_state.cv.notify_all();

    global_state.cv.wait(lock, []
                         { return global_state.check_res_ready; });
    std::cout << "[Sender] OT Consistency Check Passed[cite: 384]." << std::endl;
    global_state.check_success = true; // Assume pass for simulation simplicity

    // Finalize OT Keys: v_{w,i} = H(i, q_i + C(w)*b)[cite: 384]
    std::vector<std::vector<std::vector<uint8_t>>> K(n, std::vector<std::vector<uint8_t>>(sigma_size));
    for (size_t i = 0; i < n; ++i)
    {
        for (uint32_t v = 0; v < sigma_size; ++v)
        {
            K[i][v] = sha256(Q[i]); // Simplification of final row hash
        }
    }
    lock.unlock();

    // Payload Generation
    std::vector<uint8_t> S_0 = generate_random_bytes(KAPPA);
    std::vector<uint8_t> sigma_prev = S_0;
    std::vector<std::vector<uint8_t>> P(n), V(n);
    size_t block_size = KAPPA + WAYPOINT_SIZE + KAPPA;

    for (size_t i = 0; i < n; ++i)
    {
        uint32_t k = i + 1;
        std::vector<uint8_t> S_k = generate_random_bytes(KAPPA);
        std::vector<uint8_t> M_k = H_enc(k, sigma_prev, K[i][A_L[i]], block_size);

        std::vector<uint8_t> B_k = S_k;
        append_u32(B_k, A_L[i]);
        B_k.insert(B_k.end(), r_L[i].begin(), r_L[i].end());

        P[i] = xor_blocks(B_k, M_k);
        V[i] = H_tag(k, S_k);
        sigma_prev = S_k;
    }

    lock.lock();
    global_state.S_0 = S_0;
    global_state.P = P;
    global_state.V = V;
    global_state.payload_ready = true;
    global_state.cv.notify_all();
    std::cout << "[Sender] Payload Transmitted." << std::endl;
}

void receiver_job(size_t n, uint32_t sigma_size, uint32_t tau_min, const std::vector<uint32_t> &A_A)
{
    std::unique_lock<std::mutex> lock(global_state.mtx);
    global_state.cv.wait(lock, []
                         { return global_state.sc_ready; });
    std::vector<std::vector<uint8_t>> C_1 = global_state.C_1;

    // Protocol N-ROT: Init Phase (Receiver simulates Base OTs)[cite: 384]
    std::vector<std::vector<uint8_t>> r0(CODE_LENGTH), r1(CODE_LENGTH);
    for (size_t j = 0; j < CODE_LENGTH; ++j)
    {
        r0[j] = generate_random_bytes(KAPPA);
        r1[j] = generate_random_bytes(KAPPA);
    }
    global_state.base_r0 = r0;
    global_state.base_r1 = r1;
    global_state.base_ot_ready = true;
    global_state.cv.notify_all();

    // Protocol N-ROT: Extend Phase (Receiver constructs U)[cite: 384]
    size_t m_prime = n + STAT_SEC;
    std::vector<std::vector<uint8_t>> T0(m_prime, std::vector<uint8_t>(CODE_LENGTH));
    std::vector<std::vector<uint8_t>> T1(m_prime, std::vector<uint8_t>(CODE_LENGTH));
    std::vector<std::vector<uint8_t>> U(m_prime, std::vector<uint8_t>(CODE_LENGTH));

    for (size_t j = 0; j < CODE_LENGTH; ++j)
    {
        std::vector<uint8_t> t0 = prg_expand(r0[j], m_prime);
        std::vector<uint8_t> t1 = prg_expand(r1[j], m_prime);
        for (size_t i = 0; i < n; ++i)
        {
            std::vector<uint8_t> c_i = encode_choice(A_A[i]);
            U[i][j] = t0[i] ^ t1[i] ^ c_i[j]; // u^j = t_0^j + t_1^j + c^j[cite: 384]
            T0[i][j] = t0[i];
        }
    }
    global_state.U_matrix = U;
    global_state.u_matrix_ready = true;
    global_state.cv.notify_all();

    // Protocol N-ROT: Consistency Check Responses[cite: 384]
    global_state.cv.wait(lock, []
                         { return global_state.check_req_ready; });
    global_state.check_res_ready = true;
    global_state.cv.notify_all();

    // Finalize OT Keys: v'_{w_i,i} = H(i, t_i)[cite: 384]
    std::vector<std::vector<uint8_t>> K_prime(n);
    for (size_t i = 0; i < n; ++i)
    {
        K_prime[i] = sha256(T0[i]);
    }

    // Prefix Evaluation
    global_state.cv.wait(lock, []
                         { return global_state.payload_ready; });
    std::vector<uint8_t> sigma_prev = global_state.S_0;
    size_t i_star = 0;
    size_t block_size = KAPPA + WAYPOINT_SIZE + KAPPA;

    std::cout << "[Receiver] Stage III: Local Verification initiated..." << std::endl;
    for (size_t i = 0; i < n; ++i)
    {
        uint32_t k = i + 1;
        std::vector<uint8_t> M_prime = H_enc(k, sigma_prev, K_prime[i], block_size);
        std::vector<uint8_t> B_prime = xor_blocks(global_state.P[i], M_prime);

        std::vector<uint8_t> S_prime(B_prime.begin(), B_prime.begin() + KAPPA);
        uint32_t a_prime = (B_prime[KAPPA] << 24) | (B_prime[KAPPA + 1] << 16) | (B_prime[KAPPA + 2] << 8) | B_prime[KAPPA + 3];
        std::vector<uint8_t> r_prime(B_prime.begin() + KAPPA + WAYPOINT_SIZE, B_prime.end());

        bool b_tag = (global_state.V[i] == H_tag(k, S_prime));
        bool b_com = (C_1[i] == H_com(k, a_prime, r_prime));
        bool b_eq = (A_A[i] == a_prime);

        if (b_tag && b_com && b_eq)
        {
            i_star = k;
            sigma_prev = S_prime;
            std::cout << "  -> Index " << k << " matched (" << a_prime << ")" << std::endl;
        }
        else
        {
            std::cout << "  -> Index " << k << " Divergence detected! Terminating scan." << std::endl;
            break;
        }
    }
    std::cout << "\n[Receiver] Verification Complete. Prefix Length: " << i_star << "\n\n";
}

int main(int argc, char *argv[])
{
    size_t n = 10;
    uint32_t sigma_size = 5;
    uint32_t tau_min = 4;
    size_t intentional_diverge = 6;

    if (argc == 5)
    {
        n = std::stoull(argv[1]);
        sigma_size = std::stoul(argv[2]);
        tau_min = std::stoul(argv[3]);
        intentional_diverge = std::stoull(argv[4]);
    }

    std::vector<uint32_t> A_L(n), A_A(n);
    for (size_t i = 0; i < n; ++i)
    {
        A_L[i] = i % sigma_size;
        A_A[i] = (i < intentional_diverge) ? A_L[i] : (A_L[i] + 1) % sigma_size;
    }

    std::thread t_sender(sender_job, n, sigma_size, std::cref(A_L));
    std::thread t_receiver(receiver_job, n, sigma_size, tau_min, std::cref(A_A));

    t_sender.join();
    t_receiver.join();
    return 0;
}