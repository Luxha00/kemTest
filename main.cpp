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

// Funkcija za pridobivanje procesorjevih ciklov
inline uint64_t rdtsc() {
    return __rdtsc();
}

// Funkcija za odstranjevanje osamelcev (odstrani zadnjih x% vrednosti)
void remove_outliers(std::vector<uint64_t>& data, int percentile) {
    if (data.empty()) return;

    size_t remove_count = data.size() * percentile / 100;
    if (remove_count == 0) return;

    std::sort(data.begin(), data.end());
    data.resize(data.size() - remove_count);
}

void test_kem(const char* kem_name, std::ofstream& file, int iterations) {
    OQS_KEM* kem = OQS_KEM_new(kem_name);
    if (!kem) {
        std::cerr << "Algoritem " << kem_name << " ni podprt!\n";
        return;
    }

    std::vector<uint64_t> keygen_times, encaps_times, decaps_times;

    for (int i = 0; i < iterations; ++i) {
        // Alokacija pomnilnika
        std::vector<uint8_t> public_key(kem->length_public_key);
        std::vector<uint8_t> secret_key(kem->length_secret_key);
        std::vector<uint8_t> ciphertext(kem->length_ciphertext);
        std::vector<uint8_t> shared_secret_e(kem->length_shared_secret);
        std::vector<uint8_t> shared_secret_d(kem->length_shared_secret);

        // Generiranje ključev
        uint64_t start = rdtsc();
        OQS_STATUS rc = OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
        uint64_t end = rdtsc();
        if (rc != OQS_SUCCESS) {
            std::cerr << "Napaka pri generiranju ključev za " << kem_name << "\n";
            continue;
        }
        keygen_times.push_back(end - start);

        // Inkapsulacija
        start = rdtsc();
        rc = OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_e.data(), public_key.data());
        end = rdtsc();
        if (rc != OQS_SUCCESS) {
            std::cerr << "Napaka pri inkapsulaciji za " << kem_name << "\n";
            continue;
        }
        encaps_times.push_back(end - start);

        // Dekapsulacija
        start = rdtsc();
        rc = OQS_KEM_decaps(kem, shared_secret_d.data(), ciphertext.data(), secret_key.data());
        end = rdtsc();
        if (rc != OQS_SUCCESS) {
            std::cerr << "Napaka pri dekapsulaciji za " << kem_name << "\n";
            continue;
        }
        decaps_times.push_back(end - start);
    }

    // Odstrani osamelce (5%)
    remove_outliers(keygen_times, 5);
    remove_outliers(encaps_times, 5);
    remove_outliers(decaps_times, 5);

    // Shrani povprečne vrednosti
    auto avg = [](const std::vector<uint64_t>& v) {
        return v.empty() ? 0 : std::accumulate(v.begin(), v.end(), 0ULL) / v.size();
    };

    file << kem_name << ",keygen," << avg(keygen_times) << "\n";
    file << kem_name << ",encaps," << avg(encaps_times) << "\n";
    file << kem_name << ",decaps," << avg(decaps_times) << "\n";

    OQS_KEM_free(kem);
}

int main() {
    // Povečaj prioriteto procesa
    #ifdef _WIN32
        SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    #else
        setpriority(PRIO_PROCESS, 0, -20);  // Nastavi na -20 (max prioriteta)
        sched_param param;
        param.sched_priority = sched_get_priority_max(SCHED_FIFO);
        sched_setscheduler(0, SCHED_FIFO, &param);
    #endif

    OQS_init();

    // Konfiguracija testa
    const int ITERATIONS = 1000;
    const char* KEM_ALGORITHMS[] = {
    "Kyber512",           // Kyber, varnostni nivo 1 (ali Kyber768/1024 za višje nivoje)
    "NTRU-HPS-2048-509",  // NTRU HPS L1
    "Saber-KEM",          // Saber, NIST L3
    "Classic-McEliece",   // liboqs: "Classic-McEliece" (če je vgrajen)
    "FrodoKEM-640-AES"    // FrodoKEM, varnostni nivo 1
    };

    std::ofstream file("kem_results.csv");
    file << "algorithm,operation,cycles\n";  // Glava CSV

    for (const auto& alg : KEM_ALGORITHMS) {
        std::cout << "Testiram " << alg << "...\n";
        test_kem(alg, file, ITERATIONS);
    }

    file.close();
    OQS_destroy();
    return 0;
}
