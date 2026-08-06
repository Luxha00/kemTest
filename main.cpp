#include <oqs/oqs.h>
#include <vector>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <numeric>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <sched.h>
#include <sys/resource.h>
#include <x86intrin.h>
#endif

// ---------------------------------------------------------------------
// Merjenje procesorskih ciklov
//
// POPRAVEK: rdtsc() sam po sebi NI serializiran ukaz - procesor ga lahko
// zaradi izvajanja izven vrstnega reda (out-of-order execution) prebere
// prezgodaj ali prepozno glede na dejansko mejo merjene kode. Zato:
//   - pred začetkom meritve pokličemo lfence(), ki počaka, da so vsi
//     predhodni ukazi dokončani, preden se prebere TSC;
//   - ob koncu meritve uporabimo rdtscp() namesto rdtsc() - rdtscp je
//     sam po sebi delno serializiran (počaka, da so predhodni ukazi
//     dokončani), dodatni lfence() po njem pa prepreči, da bi se
//     naslednji (netajmani) ukazi začeli izvajati prezgodaj in tako
//     vplivali na naslednjo meritev.
// Priporočilo: Intel, "How to Benchmark Code Execution Times on
// Intel IA-32 and IA-64 Instruction Set Architectures" (CPUID/RDTSC ...
// RDTSCP/CPUID vzorec).
// ---------------------------------------------------------------------
inline uint64_t rdtsc_start() {
    _mm_lfence();
    return __rdtsc();
}

inline uint64_t rdtsc_end() {
    unsigned int aux;
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

// Število iteracij ogrevanja, ki se izvedejo, a NE zapišejo v izhodno
// datoteko. Ogrevanje zapolni predpomnilnike (cache), inicializira
// napovedovalnik vej (branch predictor) in odpravi vpliv "hladnega
// zagona" prvih klicev na izmerjene čase.
constexpr int WARMUP_ITERATIONS = 100;

void test_kem(const char* kem_name, std::ofstream& file, int iterations) {
    OQS_KEM* kem = OQS_KEM_new(kem_name);
    if (!kem) {
        std::cerr << "Algoritem " << kem_name << " ni podprt!\n";
        return;
    }

    // POPRAVEK: medpomnilniki se alocirajo SAMO ENKRAT, izven zanke, in se
    // v vseh iteracijah ponovno uporabljajo. Prej se je std::vector
    // alociral znova v vsaki iteraciji, kar je v meritev vnašalo dodaten,
    // s kriptografsko operacijo nepovezan šum zaradi alokatorja
    // pomnilnika (malloc/heap management) in morebitnih page faultov.
    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret_e(kem->length_shared_secret);
    std::vector<uint8_t> shared_secret_d(kem->length_shared_secret);

    const int total_iterations = WARMUP_ITERATIONS + iterations;

    for (int i = 0; i < total_iterations; ++i) {
        const bool record = (i >= WARMUP_ITERATIONS);
        uint64_t start, end;

        // Keygen
        start = rdtsc_start();
        OQS_STATUS rc = OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
        end = rdtsc_end();
        if (rc != OQS_SUCCESS) {
            std::cerr << "Napaka pri generiranju ključev za " << kem_name << "\n";
            continue;
        }
        if (record) file << kem_name << ",keygen," << (end - start) << "\n";

        // Encaps
        start = rdtsc_start();
        rc = OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_e.data(), public_key.data());
        end = rdtsc_end();
        if (rc != OQS_SUCCESS) {
            std::cerr << "Napaka pri inkapsulaciji za " << kem_name << "\n";
            continue;
        }
        if (record) file << kem_name << ",encaps," << (end - start) << "\n";

        // Decaps
        start = rdtsc_start();
        rc = OQS_KEM_decaps(kem, shared_secret_d.data(), ciphertext.data(), secret_key.data());
        end = rdtsc_end();
        if (rc != OQS_SUCCESS) {
            std::cerr << "Napaka pri dekapsulaciji za " << kem_name << "\n";
            continue;
        }
        if (record) file << kem_name << ",decaps," << (end - start) << "\n";
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
    sched_setscheduler(0, SCHED_FIFO, &param);
#endif

    OQS_init();

    const int ITERATIONS = 1000;

    const char* KEM_ALGORITHMS[] = {
        // BIKE
        "BIKE-L1", "BIKE-L3", "BIKE-L5",

        // Classic McEliece
        // POPRAVEK: prej zakomentirano - a Classic-McEliece-* rezultati SO
        // prisotni v končnem podatkovnem naboru (combined_full.csv), zato
        // mora biti ta program tisti, ki jih dejansko generira, sicer
        // rezultatov ni mogoče ponoviti iz objavljene kode.
        "Classic-McEliece-348864", "Classic-McEliece-348864f",
        "Classic-McEliece-460896", "Classic-McEliece-460896f",
        "Classic-McEliece-6688128", "Classic-McEliece-6688128f",
        "Classic-McEliece-6960119", "Classic-McEliece-6960119f",
        "Classic-McEliece-8192128", "Classic-McEliece-8192128f",

        // HQC (referenčna/liboqs različica - glej opombo spodaj)
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
    // OPOMBA: kot je opisano v poglavju 4 naloge, so bili rezultati za
    // optimizirano AVX2 različico HQC (v podatkih označeni kot
    // HQC-1/3/5-AVX2) pridobljeni ločeno, z uradno implementacijo iz
    // gitlab.com/pqc-hqc/hqc, saj je liboqs 0.15.0 ne vsebuje. Ta program
    // meri samo referenčno liboqs različico HQC-128/192/256.

    std::ofstream file("kem_raw_data.csv");
    file << "algorithm,operation,cycles\n";

    size_t num_algs = sizeof(KEM_ALGORITHMS) / sizeof(KEM_ALGORITHMS[0]);

    std::cout << "Enabled KEMs in this liboqs:\n";
    for (size_t i = 0; i < OQS_KEM_alg_count(); i++) {
        std::cout << " - " << OQS_KEM_alg_identifier(i) << "\n";
    }

    auto total_start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < num_algs; ++i) {
        const char* alg = KEM_ALGORITHMS[i];
        if (OQS_KEM_alg_is_enabled(alg)) {
            std::cout << "Testiram " << alg << "...";
            std::cout.flush();

            auto alg_start = std::chrono::high_resolution_clock::now();
            test_kem(alg, file, ITERATIONS);
            auto alg_end = std::chrono::high_resolution_clock::now();
            auto alg_duration = std::chrono::duration_cast<std::chrono::seconds>(alg_end - alg_start);

            std::cout << " končano (" << alg_duration.count() << "s)\n";
        } else {
            std::cout << "OPOZORILO: " << alg << " ni podprt, preskočen.\n";
        }
    }

    auto total_end = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::minutes>(total_end - total_start);

    std::cout << "\nCELOTNI TEST KONČAN\n";
    std::cout << "Skupni čas izvajanja: " << total_duration.count() << " minut\n";

    file.close();
    OQS_destroy();
    return 0;
}
