#pragma once
#include <vector>
#include <mutex>
#include <nvs.h>
#include "DDKReaderData.h"
#include "msgpack/object.h"
#include "msgpack/pack.h"

/**
 * @class ReaderDataManager
 * @brief Manages the lifecycle of HomeKey reader data (readerData_t).
 *
 * This class handles loading, saving, modifying, and deleting the dynamic
 * HomeKey provisioning data from NVS. It ensures that operations are
 * performed safely and provides a single point of access to this critical data.
 */
class ReaderDataManager {
public:
    ReaderDataManager();
    ~ReaderDataManager();

    bool begin();

    const readerData_t& getReaderData() const;
    readerData_t getReaderDataCopy() const;
    const std::vector<uint8_t>& getReaderGid() const;
    const std::vector<uint8_t>& getReaderId() const;

    const readerData_t* updateReaderData(const readerData_t& newData);
    bool eraseReaderKey();
    bool deleteAllReaderData();
    bool addIssuerIfNotExists(const std::vector<uint8_t>& issuerId, const uint8_t* publicKey);
    const readerData_t* saveData();

    /**
     * @brief Enroll an Android device as a HomeKey endpoint.
     *
     * Creates a synthetic issuer keyed by the first 8 bytes of the public key
     * X coordinate and registers the Android device as an endpoint under it.
     * Does NOT save to NVS automatically - call saveData() after.
     *
     * @param endpointId             6-byte device identifier (from Android
     *                               HomeKeyCrypto.getDeviceIdentifier())
     * @param publicKeyUncompressed  65-byte uncompressed secp256r1 public key
     *                               (0x04 prefix + 32-byte X + 32-byte Y)
     * @return true if enrolled, false if already present or input is invalid
     */
    bool addAndroidEndpoint(const std::vector<uint8_t>& endpointId,
                            const std::vector<uint8_t>& publicKeyUncompressed);

    /**
     * @brief Remove a previously enrolled Android device endpoint.
     *
     * Does NOT save to NVS automatically - call saveData() after.
     *
     * @param endpointId  6-byte device identifier to remove
     * @return true if found and removed, false if not found
     */
    bool removeAndroidEndpoint(const std::vector<uint8_t>& endpointId);

private:
    void load();

    void unpack_readerData_t(msgpack_object obj, readerData_t& reader_data);
    void pack_readerData_t(msgpack_packer* pk, const readerData_t& reader_data);
    void unpack_hkIssuer_t(msgpack_object obj, hkIssuer_t& issuer);
    void pack_hkIssuer_t(msgpack_packer* pk, const hkIssuer_t& issuer);
    void unpack_hkEndpoint_t(msgpack_object obj, hkEndpoint_t& endpoint);
    void pack_hkEndpoint_t(msgpack_packer* pk, const hkEndpoint_t& endpoint);

    readerData_t m_readerData;
    mutable std::mutex m_readerDataMutex;
    nvs_handle m_nvsHandle;
    bool m_isInitialized;

    static const char* TAG;
    static const char* NVS_KEY;
};
