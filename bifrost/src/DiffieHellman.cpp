#include <DiffieHellman.hpp>
#include <Random.hpp>
#include <TypeDefs.hpp>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <utility.hpp>

using json = nlohmann::json;

Bytes generatePrivateSecret() {
    Bytes privKey = numToBytes(Random::generatePrimeNum(PRIVATE_SECRET_LENGTH));
    return resizeKey(privKey, KEY_SIZE);
}

Bytes generateSharedSecret(const std::string &serverRegCode) {
    Bytes privateKey = generatePrivateSecret();
    Bytes pubKey = numToBytes(powMod(DH_GEN, bytesToNum(privateKey), DH_PRIME));

    std::cout << "Generated DH Private Key: " << bytesToHex(privateKey)
              << std::endl;
    std::cout << "Generated DH Public  key: " << bytesToHex(pubKey)
              << std::endl;
    Bytes serverPublicKey = getServerPublicKey(pubKey, serverRegCode);
    if (serverPublicKey.empty())
        return {};
    std::cout << "Received Server DH Public Key: "
              << bytesToHex(serverPublicKey) << std::endl;

    Bytes secretKey = numToBytes(
        powMod(bytesToNum(serverPublicKey), bytesToNum(privateKey), DH_PRIME));
    secretKey = resizeKey(secretKey, KEY_SIZE);
    std::cout << "Computed Shared Secret Key: " << bytesToHex(secretKey)
              << std::endl;
    return secretKey;
}

Bytes getServerPublicKey(const Bytes &pubKey,
                         const std::string &serverRegCode) {
    std::string pubKeyStr = bytesToHex(pubKey);
    json payload = {{"bifrost-public-key", pubKeyStr}};

    cpr::Response r = cpr::Post(
        cpr::Url{SERVER_URL + serverRegCode}, cpr::Body{payload.dump()},
        cpr::Header{{"Content-Type", "application/json"}});

    Bytes serverkey;
    if (r.status_code == 200 || r.status_code == 201) {
        try {
            json response_data = json::parse(r.text);

            if (response_data.contains("server-public-key")) {
                serverkey = numToBytes(num_t(
                    "0x" + std::string(response_data["server-public-key"])));
                serverkey = resizeKey(serverkey, KEY_SIZE);
            } else {
                std::cerr
                    << "Required fields not found in response. Raw response:\n"
                    << response_data.dump(4) << std::endl;
                return {};
            }

        } catch (const json::parse_error &e) {
            std::cerr << "Failed to parse API response as JSON: " << e.what()
                      << std::endl;
            return {};
        }
    } else {
        std::cerr << "HTTP Error occurred!" << std::endl;
        std::cerr << "Status Code: " << r.status_code << std::endl;
        std::cerr << "Error Message: " << r.error.message << std::endl;
        return {};
    }
    return serverkey;
}

Bytes resizeKey(const Bytes &key, const int nBytes) {
    if (key.size() >= nBytes) {
        return Bytes(key.end() - nBytes, key.end());
    }
    Bytes padded(nBytes);
    std::memset(padded.data(), 0, nBytes);
    for (auto it = padded.begin() + nBytes - key.size(); it != padded.end();
         it++)
        *it = key[it - padded.begin() + key.size() - nBytes];
    return padded;
}
