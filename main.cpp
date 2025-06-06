#include <oqs/oqs.h>
#include <vector>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <numeric>
#ifdef _WIN32
#include <windows.h>
#else
#include <sched.h>
#include <sys/resource.h>
#endif
#ifdef __linux__
#include <x86intrin.h>
#else
#include <intrin.h>
#endif

inline uint64_t rdtsc() {
    return __rdtsc();
}

void test_kem(const char* kem_name, std::ofstream& file, int iterations) {
    OQS_KEM* kem = OQS_KEM_new(kem_name);
    if (!kem) {
        std::cerr << "Algoritem " << kem_name << " ni podprt!\n";
        return;
    }

    for (int i = 0; i < iterations; ++i) {
        std::vector<uint8_t> public_key(kem->length_public_key);
        std::vector<uint8_t> secret_key(kem->length_secret_key);
        std::vector<uint8_t> ciphertext(kem->length_ciphertext);
        std::vector<uint8_t> shared_secret_e(kem->length_shared_secret);
        std::vector<uint8_t> shared_secret_d(kem->length_shared_secret);

        // Keygen
        uint64_t start = rdtsc();
        OQS_STATUS rc = OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
        uint64_t end = rdtsc();
        if (rc != OQS_SUCCESS) {
            std::cerr << "Napaka pri generiranju ključev za " << kem_name << "\n";
            continue;
        }
        file << kem_name << ",keygen," << (end - start) << "\n";

        // Encaps
        start = rdtsc();
        rc = OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_e.data(), public_key.data());
        end = rdtsc();
        if (rc != OQS_SUCCESS) {
            std::cerr << "Napaka pri inkapsulaciji za " << kem_name << "\n";
            continue;
        }
        file << kem_name << ",encaps," << (end - start) << "\n";

        // Decaps
        start = rdtsc();
        rc = OQS_KEM_decaps(kem, shared_secret_d.data(), ciphertext.data(), secret_key.data());
        end = rdtsc();
        if (rc != OQS_SUCCESS) {
            std::cerr << "Napaka pri dekapsulaciji za " << kem_name << "\n";
            continue;
        }
        file << kem_name << ",decaps," << (end - start) << "\n";
    }

    OQS_KEM_free(kem);
}

int main() {
    #ifdef _WIN32
        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    #else
        setpriority(PRIO_PROCESS, 0, -20);
        sched_param param;
        param.sched_priority = sched_get_priority_max(SCHED_FIFO);
        if (sched_setscheduler(0, SCHED_FIFO, &param) {
            perror("sched_setscheduler failed");
        }
    #endif

    OQS_init();

    const int ITERATIONS = 1000;
    const char* KEM_ALGORITHMS[] = {
        // BIKE
        "BIKE-L1", "BIKE-L3", "BIKE-L5",
        
        // Classic McEliece
        "Classic-McEliece-348864", "Classic-McEliece-348864f",
        "Classic-McEliece-460896", "Classic-McEliece-460896f",
        "Classic-McEliece-6688128", "Classic-McEliece-6688128f",
        "Classic-McEliece-6960119", "Classic-McEliece-6960119f",
        "Classic-McEliece-8192128", "Classic-McEliece-8192128f",
        
        // HQC
        "HQC-128", "HQC-192", "HQC-256",
        
        // ML-KEM (Kyber)
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        
        // NTRU Prime
        "sntrup761",
        
        // FrodoKEM
        "FrodoKEM-640-AES", "FrodoKEM-640-SHAKE",
        "FrodoKEM-976-AES", "FrodoKEM-976-SHAKE",
        "FrodoKEM-1344-AES", "FrodoKEM-1344-SHAKE"
    };

    std::ofstream file("kem_raw_data.csv");
    file << "algorithm,operation,cycles\n";

    size_t num_algs = sizeof(KEM_ALGORITHMS) / sizeof(KEM_ALGORITHMS[0]);
    for (size_t i = 0; i < num_algs; ++i) {
        const char* alg = KEM_ALGORITHMS[i];
        if (OQS_KEM_alg_is_enabled(alg)) {
            std::cout << "Testiram " << alg << "...\n";
            test_kem(alg, file, ITERATIONS);
        } else {
            std::cout << "OPOZORILO: " << alg << " ni podprt, preskocen.\n";
        }
    }

    file.close();
    OQS_destroy();
    return 0;
}
