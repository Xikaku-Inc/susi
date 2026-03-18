#ifndef SUSI_H
#define SUSI_H

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

class SusiClient {
public:
    enum class LicenseStatus {
        Valid,
        ValidGracePeriod,
        Expired,
        LeaseExpired,
        InvalidMachine,
        InvalidSignature,
        InvalidLicenseKey,
        Revoked,
        TokenNotFound,
        FileNotFound,
        Error,
    };
private:
    bool m_isValid = false;
    std::vector<std::string> m_features;
    int64_t m_leaseExpiresEpoch = 0; // 0 = no lease
    int64_t m_graceHours = 24;
    std::string m_publicKey;
    std::string m_serverUrl;

public:
    SusiClient(std::string publicKey) : m_publicKey(std::move(publicKey)) {}
    /// Create a client with an activation server URL (e.g. "https://license.example.com/api/v1").
    SusiClient(std::string publicKey, std::string serverUrl)
        : m_publicKey(std::move(publicKey)), m_serverUrl(std::move(serverUrl)) {}

    std::string getPublicKeyPem();

    /// Checks the license file at the given path.
    LicenseStatus checkLicense(const std::filesystem::path& licensePath);
    /// Checks for a license token on attached USB devices, and verifies it if found.
    LicenseStatus checkLicenseToken();
    /// Contact the activation server to refresh the lease, then verify the license.
    /// Falls back to the cached local file if the server is unreachable.
    LicenseStatus checkLicenseAndRefresh(const std::filesystem::path& licensePath, const std::string& licenseKey);

    bool isValid() const { return m_isValid; }

    const std::vector<std::string>& features() const { return m_features; }

    bool hasFeature(const std::string& feature) const;

    /// Returns true if there is an active lease that has not yet expired.
    bool isLeaseValid() const;

    /// Returns true if the lease is expired but within the grace period.
    bool isInGracePeriod() const;

    /// Returns true if the lease is expired past the grace period.
    bool isLeaseExpired() const;

    void setGraceHours(int64_t hours) { m_graceHours = hours; }
private:
    LicenseStatus verifySignedLicenseJson(std::string signedLicenseStr, std::string activationCode = "");
};

#endif
