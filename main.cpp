#include <oqs/oqs.h>
#include <vector>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <numeric>
#include <chrono>
#include <string>

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
// rdtsc() sam po sebi NI serializiran ukaz - procesor ga lahko zaradi
// izvajanja izven vrstnega reda (out-of-order execution) prebere
// prezgodaj ali prepozno glede na dejansko mejo merjene kode. Zato:
//   - pred začetkom meritve pokličemo lfence(), ki počaka, da so vsi
//     predhodni ukazi dokončani, preden se prebere TSC;
//   - ob koncu meritve uporabimo rdtscp() namesto rdtsc() - rdtscp je
//     sam po sebi delno serializiran, dodatni lfence() po njem pa
//     prepreči, da bi se naslednji (netajmani) ukazi začeli izvajati
//     prezgodaj in tako vplivali na naslednjo meritev.
// Priporočilo: Intel, "How to Benchmark Code Execution Times on
// Intel IA-32 and IA-64 Instruction Set Architectures".
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

    // Medpomnilniki se alocirajo SAMO ENKRAT, izven zanke, in se v vseh
    // iteracijah ponovno uporabljajo (ne alocirajo znova v vsaki
    // iteraciji), da se izognemo šumu iz alokatorja pomnilnika.
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

const char* KEM_ALGORITHMS[] = {
    // BIKE
    "BIKE-L1", "BIKE-L3", "BIKE-L5",

    // Classic McEliece
    "Classic-McEliece-348864", "Classic-McEliece-348864f",
    "Classic-McEliece-460896", "Classic-McEliece-460896f",
    "Classic-McEliece-6688128", "Classic-McEliece-6688128f",
    "Classic-McEliece-6960119", "Classic-McEliece-6960119f",
    "Classic-McEliece-8192128", "Classic-McEliece-8192128f",

    // HQC (referenčna/liboqs različica)
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
// gitlab.com/pqc-hqc/hqc. Ta program meri samo referenčno liboqs
// različico HQC-128/192/256.

// Izvede en celoten krog meritev čez vse algoritme in ga zapiše v
// podano datoteko. Klicano 5x zapored iz main() - vsak klic je
// popolnoma neodvisna ponovitev (nov "sweep" čez vse algoritme), ne le
// dodatne iteracije znotraj istega algoritma.
void run_full_sweep(const std::string& output_path, int run_number, int total_runs) {
    std::ofstream file(output_path);
    file << "algorithm,operation,cycles\n";

    const int ITERATIONS = 1000;
    size_t num_algs = sizeof(KEM_ALGORITHMS) / sizeof(KEM_ALGORITHMS[0]);

    std::cout << "\n========== TEK " << run_number << " / " << total_runs
              << " -> " << output_path << " ==========\n";

    auto sweep_start = std::chrono::high_resolution_clock::now();

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

    auto sweep_end = std::chrono::high_resolution_clock::now();
    auto sweep_duration = std::chrono::duration_cast<std::chrono::minutes>(sweep_end - sweep_start);

    std::cout << "Tek " << run_number << " končan (" << sweep_duration.count() << " min). "
              << "Zapisano v " << output_path << "\n";

    file.close();
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

    std::cout << "Enabled KEMs in this liboqs:\n";
    for (size_t i = 0; i < OQS_KEM_alg_count(); i++) {
        std::cout << " - " << OQS_KEM_alg_identifier(i) << "\n";
    }

    // POPRAVEK: namesto enkratnega zagona program zdaj sam izvede 10
    // popolnoma neodvisnih ponovitev celotnega niza meritev, vsako v
    // svojo datoteko (kem_raw_data_run1.csv ... kem_raw_data_run5.csv).
    // Med posameznimi teki ni čiščenja/resetiranja stanja procesa (nov
    // OQS_KEM_new se pokliče za vsak algoritem znotraj vsakega teka),
    // kar je enako, kot če bi program petkrat ročno pognali enega za
    // drugim.
    constexpr int NUM_RUNS = 10;

    auto total_start = std::chrono::high_resolution_clock::now();

    for (int run = 1; run <= NUM_RUNS; ++run) {
        std::string filename = "kem_raw_data_run" + std::to_string(run) + ".csv";
        run_full_sweep(filename, run, NUM_RUNS);
    }

    auto total_end = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::minutes>(total_end - total_start);

    std::cout << "\nVSEH " << NUM_RUNS << " TEKOV KONČANIH\n";
    std::cout << "Skupni čas izvajanja: " << total_duration.count() << " minut\n";

    OQS_destroy();
    return 0;
}
