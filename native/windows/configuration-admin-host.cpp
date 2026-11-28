#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(GPT_REPO_CONFIGURATION_ADMIN_EXPECT_X64) && !defined(_M_X64)
#error Configuration admin host must be built for x64.
#endif
#if defined(GPT_REPO_CONFIGURATION_ADMIN_EXPECT_ARM64) && !defined(_M_ARM64)
#error Configuration admin host must be built for ARM64.
#endif
#if defined(GPT_REPO_CONFIGURATION_ADMIN_EXPECT_X86) && !defined(_M_IX86)
#error Configuration admin host must be built for x86.
#endif

namespace {

constexpr DWORD kMaximumFrameBytes = 16'384;
constexpr DWORD kMaximumInputBytes = kMaximumFrameBytes + 4;
constexpr DWORD kMaximumControlLineBytes = 32'768;
constexpr DWORD kConnectionTimeoutMs = 2'000;
constexpr DWORD kProbeTimeoutMs = 2'000;
constexpr DWORD kReloadAcknowledgmentTimeoutMs = 30'000;
constexpr DWORD kControlLineTimeoutMs = 2'000;
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
constexpr size_t kMaximumConnections = 2;
#else
constexpr size_t kMaximumConnections = 32;
#endif
constexpr DWORD kMaximumPipeInstances = 64;
constexpr DWORD kPipeBufferBytes = kMaximumInputBytes;
constexpr char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

class UniqueHandle {
 public:
  explicit UniqueHandle(HANDLE value = nullptr) : value_(value) {}
  ~UniqueHandle() { reset(); }
  UniqueHandle(const UniqueHandle &) = delete;
  UniqueHandle &operator=(const UniqueHandle &) = delete;
  UniqueHandle(UniqueHandle &&other) noexcept
      : value_(std::exchange(other.value_, nullptr)) {}
  UniqueHandle &operator=(UniqueHandle &&other) noexcept {
    if (this != &other) reset(std::exchange(other.value_, nullptr));
    return *this;
  }
  HANDLE get() const { return value_; }
  explicit operator bool() const {
    return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
  }
  void reset(HANDLE value = nullptr) {
    if (*this) CloseHandle(value_);
    value_ = value;
  }

 private:
  HANDLE value_;
};

struct SecurityContext {
  std::vector<BYTE> tokenUserBytes;
  PSID userSid = nullptr;
  PACL dacl = nullptr;
  SECURITY_DESCRIPTOR descriptor{};
  SECURITY_ATTRIBUTES attributes{};

  ~SecurityContext() {
    if (dacl != nullptr) LocalFree(dacl);
  }
};

struct InstanceRecord {
  DWORD serverPid = 0;
  DWORD helperPid = 0;
  ULONGLONG helperCreationTime = 0;
  std::string instanceId;
  std::string endpoint;
};

enum class IoWaitResult { kCompleted, kParentExited, kTimedOut, kFailed };

std::mutex g_stdoutMutex;
std::atomic<ULONGLONG> g_connectionSequence{1};

#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
const wchar_t *testFault();
bool writeTestMarker(const wchar_t *environmentName);
bool testMarkerExists(const wchar_t *environmentName);
#endif

bool isValidUuid(const std::string &value) {
  if (value.size() != 36) return false;
  for (size_t index = 0; index < value.size(); ++index) {
    const char character = value[index];
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (character != '-') return false;
    } else if (!((character >= '0' && character <= '9') ||
                 (character >= 'a' && character <= 'f'))) {
      return false;
    }
  }
  return true;
}

bool parsePositivePid(const wchar_t *value, DWORD &pid) {
  if (value == nullptr || *value == L'\0') return false;
  wchar_t *end = nullptr;
  const unsigned long parsed = wcstoul(value, &end, 10);
  if (end == value || *end != L'\0' || parsed == 0 || parsed > MAXDWORD) {
    return false;
  }
  pid = static_cast<DWORD>(parsed);
  return true;
}

bool parsePositiveUint64(const wchar_t *value, ULONGLONG &parsed) {
  if (value == nullptr || *value == L'\0' || *value == L'0') return false;
  ULONGLONG result = 0;
  constexpr ULONGLONG maximum = ~static_cast<ULONGLONG>(0);
  size_t digits = 0;
  for (const wchar_t *cursor = value; *cursor != L'\0'; ++cursor) {
    if (*cursor < L'0' || *cursor > L'9') return false;
    if (++digits > 20) return false;
    const ULONGLONG digit = static_cast<ULONGLONG>(*cursor - L'0');
    if (result > (maximum - digit) / 10) return false;
    result = result * 10 + digit;
  }
  if (result == 0) return false;
  parsed = result;
  return true;
}

bool getProcessCreationTime(HANDLE process, ULONGLONG &creationTime) {
  FILETIME creation{};
  FILETIME exit{};
  FILETIME kernel{};
  FILETIME user{};
  if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) return false;
  ULARGE_INTEGER value{};
  value.LowPart = creation.dwLowDateTime;
  value.HighPart = creation.dwHighDateTime;
  creationTime = value.QuadPart;
  if (creationTime != 0) return true;
  SetLastError(ERROR_INVALID_DATA);
  return false;
}

std::string narrowAscii(const std::wstring &value) {
  std::string result;
  result.reserve(value.size());
  for (wchar_t character : value) {
    if (static_cast<unsigned int>(character) > 0x7f) return {};
    result.push_back(static_cast<char>(character));
  }
  return result;
}

std::wstring widenAscii(const std::string &value) {
  std::wstring result;
  result.reserve(value.size());
  for (unsigned char character : value) {
    if (character > 0x7f) return {};
    result.push_back(static_cast<wchar_t>(character));
  }
  return result;
}

std::string encodeBase64(const BYTE *data, size_t size) {
  std::string output;
  output.reserve(((size + 2) / 3) * 4);
  for (size_t offset = 0; offset < size; offset += 3) {
    const DWORD first = data[offset];
    const DWORD second = offset + 1 < size ? data[offset + 1] : 0;
    const DWORD third = offset + 2 < size ? data[offset + 2] : 0;
    const DWORD value = (first << 16) | (second << 8) | third;
    output.push_back(kBase64Alphabet[(value >> 18) & 0x3f]);
    output.push_back(kBase64Alphabet[(value >> 12) & 0x3f]);
    output.push_back(offset + 1 < size ? kBase64Alphabet[(value >> 6) & 0x3f] : '=');
    output.push_back(offset + 2 < size ? kBase64Alphabet[value & 0x3f] : '=');
  }
  return output;
}

int base64Value(char value) {
  if (value >= 'A' && value <= 'Z') return value - 'A';
  if (value >= 'a' && value <= 'z') return value - 'a' + 26;
  if (value >= '0' && value <= '9') return value - '0' + 52;
  if (value == '+') return 62;
  if (value == '/') return 63;
  return -1;
}

bool decodeBase64(const std::string &value, std::vector<BYTE> &output) {
  if (value.empty() || value.size() % 4 != 0) return false;
  output.clear();
  output.reserve((value.size() / 4) * 3);
  for (size_t offset = 0; offset < value.size(); offset += 4) {
    const int a = base64Value(value[offset]);
    const int b = base64Value(value[offset + 1]);
    const bool pad2 = value[offset + 2] == '=';
    const bool pad3 = value[offset + 3] == '=';
    const int c = pad2 ? 0 : base64Value(value[offset + 2]);
    const int d = pad3 ? 0 : base64Value(value[offset + 3]);
    const bool last = offset + 4 == value.size();
    if (a < 0 || b < 0 || c < 0 || d < 0 || (!last && (pad2 || pad3)) ||
        (pad2 && !pad3)) return false;
    const DWORD bits = (static_cast<DWORD>(a) << 18) |
                       (static_cast<DWORD>(b) << 12) |
                       (static_cast<DWORD>(c) << 6) | static_cast<DWORD>(d);
    output.push_back(static_cast<BYTE>((bits >> 16) & 0xff));
    if (!pad2) output.push_back(static_cast<BYTE>((bits >> 8) & 0xff));
    if (!pad3) output.push_back(static_cast<BYTE>(bits & 0xff));
  }
  return !output.empty();
}

bool hasValidFrame(const std::vector<BYTE> &bytes) {
  if (bytes.size() < 4 || bytes.size() > kMaximumInputBytes) return false;
  const DWORD payload = (static_cast<DWORD>(bytes[0]) << 24) |
                       (static_cast<DWORD>(bytes[1]) << 16) |
                       (static_cast<DWORD>(bytes[2]) << 8) |
                       static_cast<DWORD>(bytes[3]);
  return payload > 0 && payload <= kMaximumFrameBytes &&
         bytes.size() == static_cast<size_t>(payload) + 4;
}

bool writeHandle(HANDLE handle, const BYTE *bytes, DWORD size) {
  DWORD written = 0;
  return WriteFile(handle, bytes, size, &written, nullptr) != FALSE && written == size;
}

bool writeStdout(const std::string &value) {
  std::lock_guard<std::mutex> lock(g_stdoutMutex);
  return writeHandle(GetStdHandle(STD_OUTPUT_HANDLE),
                     reinterpret_cast<const BYTE *>(value.data()),
                     static_cast<DWORD>(value.size()));
}

bool writeStdoutBytes(const BYTE *bytes, DWORD size) {
  std::lock_guard<std::mutex> lock(g_stdoutMutex);
  return writeHandle(GetStdHandle(STD_OUTPUT_HANDLE), bytes, size);
}

bool readAllInput(HANDLE input, DWORD maximum, std::vector<BYTE> &bytes) {
  bytes.clear();
  BYTE buffer[4096];
  for (;;) {
    DWORD count = 0;
    if (!ReadFile(input, buffer, sizeof(buffer), &count, nullptr)) {
      const DWORD error = GetLastError();
      if (error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF) return true;
      return false;
    }
    if (count == 0) return true;
    if (bytes.size() + count > maximum) return false;
    bytes.insert(bytes.end(), buffer, buffer + count);
  }
}

// Grants full access to this process's user SID and protects the ACL from inheritance.
bool createSecurityContext(SecurityContext &security) {
  UniqueHandle token;
  HANDLE rawToken = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) return false;
  token.reset(rawToken);
  DWORD required = 0;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0, &required);
  if (required == 0) return false;
  security.tokenUserBytes.resize(required);
  if (!GetTokenInformation(token.get(), TokenUser, security.tokenUserBytes.data(),
                           required, &required)) return false;
  security.userSid = reinterpret_cast<TOKEN_USER *>(security.tokenUserBytes.data())->User.Sid;

  EXPLICIT_ACCESSW entry{};
  entry.grfAccessPermissions = GENERIC_ALL;
  entry.grfAccessMode = SET_ACCESS;
  entry.grfInheritance = NO_INHERITANCE;
  entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
  entry.Trustee.ptstrName = static_cast<LPWSTR>(security.userSid);
  if (SetEntriesInAclW(1, &entry, nullptr, &security.dacl) != ERROR_SUCCESS) return false;
  if (!InitializeSecurityDescriptor(&security.descriptor, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorOwner(&security.descriptor, security.userSid, FALSE) ||
      !SetSecurityDescriptorDacl(&security.descriptor, TRUE, security.dacl, FALSE) ||
      !SetSecurityDescriptorControl(&security.descriptor, SE_DACL_PROTECTED,
                                    SE_DACL_PROTECTED)) return false;
  security.attributes.nLength = static_cast<DWORD>(sizeof(SECURITY_ATTRIBUTES));
  security.attributes.lpSecurityDescriptor = &security.descriptor;
  security.attributes.bInheritHandle = FALSE;
  return true;
}

// Accepts only objects owned by this user with one non-inherited full-control ACE.
bool hasOwnerOnlyDacl(HANDLE handle, const SecurityContext &security,
                      SE_OBJECT_TYPE objectType) {
  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const DWORD error = GetSecurityInfo(handle, objectType,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr,
      &dacl, nullptr, &descriptor);
  if (error != ERROR_SUCCESS) return false;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  bool valid = GetSecurityDescriptorControl(descriptor, &control, &revision) != FALSE &&
               (control & SE_DACL_PROTECTED) != 0 &&
               owner != nullptr && EqualSid(owner, security.userSid) != FALSE &&
               dacl != nullptr;
  if (valid) {
    ACL_SIZE_INFORMATION information{};
    valid = GetAclInformation(dacl, &information, sizeof(information), AclSizeInformation) != FALSE &&
            information.AceCount == 1;
  }
  if (valid) {
    LPVOID rawAce = nullptr;
    valid = GetAce(dacl, 0, &rawAce) != FALSE;
    if (valid) {
      const auto *header = static_cast<ACE_HEADER *>(rawAce);
      valid = header->AceType == ACCESS_ALLOWED_ACE_TYPE && header->AceFlags == 0;
      if (valid) {
        const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(rawAce);
        PSID aceSid = const_cast<DWORD *>(&ace->SidStart);
        // The .NET pipe API's FullControl mask omits file rights that pipes do not use.
        constexpr DWORD kPipeAccessRightsFullControl = 0x001F019F;
        const bool grantsFullAccess = ace->Mask == GENERIC_ALL ||
                                      ace->Mask == FILE_ALL_ACCESS ||
                                      (objectType == SE_KERNEL_OBJECT &&
                                       ace->Mask == kPipeAccessRightsFullControl);
        valid = grantsFullAccess && EqualSid(aceSid, security.userSid) != FALSE;
      }
    }
  }
  if (descriptor != nullptr) LocalFree(descriptor);
  return valid;
}

bool verifyFileHandle(HANDLE handle, const SecurityContext &security, bool directory) {
  BY_HANDLE_FILE_INFORMATION information{};
  if (!GetFileInformationByHandle(handle, &information)) return false;
  const bool isDirectory = (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  const bool isReparse = (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
  return isDirectory == directory && !isReparse && information.nNumberOfLinks == 1 &&
         hasOwnerOnlyDacl(handle, security, SE_FILE_OBJECT);
}

bool pathHasUnsafeComponent(const std::wstring &path) {
  if (path.size() < 3 || path[1] != L':' || path[2] != L'\\' ||
      path.rfind(LR"(\\)", 0) == 0 || path.find(LR"(\\?\)") == 0 ||
      path.find(LR"(\\.\)") == 0 || path.find(L"..") != std::wstring::npos) return true;
  const std::wstring root = path.substr(0, 3);
  if (GetDriveTypeW(root.c_str()) != DRIVE_FIXED) return true;
  std::wstring current = root;
  size_t position = 3;
  while (position < path.size()) {
    const size_t separator = path.find(L'\\', position);
    const size_t end = separator == std::wstring::npos ? path.size() : separator;
    if (end == position) return true;
    current.append(path, position, end - position);
    const DWORD attributes = GetFileAttributesW(current.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) return true;
    if (separator == std::wstring::npos) break;
    current.push_back(L'\\');
    position = separator + 1;
  }
  return false;
}

bool getLocalAppData(std::wstring &path) {
  std::vector<wchar_t> buffer(32768);
  const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", buffer.data(),
                                               static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size()) return false;
  path.assign(buffer.data(), length);
  if (!path.empty() && path.back() == L'\\') path.pop_back();
  return !pathHasUnsafeComponent(path);
}

bool openVerifiedDirectory(const std::wstring &path, const SecurityContext &security,
                           HANDLE &output) {
  HANDLE raw = CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (raw == INVALID_HANDLE_VALUE) return false;
  if (!verifyFileHandle(raw, security, true)) {
    CloseHandle(raw);
    return false;
  }
  output = raw;
  return true;
}

bool createOrVerifyDirectory(const std::wstring &path, SecurityContext &security,
                            int *failureCode = nullptr, int createFailureCode = 0,
                            int verifyFailureCode = 0) {
  if (CreateDirectoryW(path.c_str(), &security.attributes) == FALSE) {
    const DWORD error = GetLastError();
    if (error != ERROR_ALREADY_EXISTS) {
      if (failureCode != nullptr) *failureCode = createFailureCode;
      return false;
    }
  }
  HANDLE directory = nullptr;
  if (!openVerifiedDirectory(path, security, directory)) {
    if (failureCode != nullptr) *failureCode = verifyFailureCode;
    return false;
  }
  CloseHandle(directory);
  return true;
}

// Locates the per-user discovery directory and optionally creates its secured path.
constexpr int kServeLocalAppDataRejected = 50;
constexpr int kServeAdminRootSetupFailed = 51;
constexpr int kServeAdminDirectorySetupFailed = 52;
constexpr int kServeAdminRootCreateFailed = 53;
constexpr int kServeAdminRootVerifyFailed = 54;

bool getAdminDirectory(SecurityContext &security, bool create,
                       std::wstring &directory, bool &exists,
                       int *createFailureCode = nullptr) {
  exists = false;
  std::wstring localAppData;
  if (!getLocalAppData(localAppData)) {
    if (create && createFailureCode != nullptr) *createFailureCode = kServeLocalAppDataRejected;
    return false;
  }
  const std::wstring root = localAppData + L"\\GPTRepoMCP";
  directory = root + L"\\admin";
  if (create) {
    int rootFailureCode = kServeAdminRootSetupFailed;
    if (!createOrVerifyDirectory(root, security, &rootFailureCode,
                                 kServeAdminRootCreateFailed,
                                 kServeAdminRootVerifyFailed)) {
      if (createFailureCode != nullptr) *createFailureCode = rootFailureCode;
      return false;
    }
    if (!createOrVerifyDirectory(directory, security)) {
      if (createFailureCode != nullptr) *createFailureCode = kServeAdminDirectorySetupFailed;
      return false;
    }
    exists = true;
    return true;
  }

  const DWORD rootAttributes = GetFileAttributesW(root.c_str());
  if (rootAttributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND) return true;
  if (rootAttributes == INVALID_FILE_ATTRIBUTES ||
      (rootAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
      (rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) return false;
  HANDLE rootHandle = nullptr;
  if (!openVerifiedDirectory(root, security, rootHandle)) return false;
  CloseHandle(rootHandle);
  const DWORD adminAttributes = GetFileAttributesW(directory.c_str());
  if (adminAttributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND) return true;
  if (adminAttributes == INVALID_FILE_ATTRIBUTES ||
      (adminAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
      (adminAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) return false;
  HANDLE adminHandle = nullptr;
  if (!openVerifiedDirectory(directory, security, adminHandle)) return false;
  CloseHandle(adminHandle);
  exists = true;
  return true;
}

std::wstring pipeName(DWORD serverPid, const std::string &instanceId) {
  return L"\\\\.\\pipe\\gpt-repo-mcp-" + std::to_wstring(serverPid) + L"-" + widenAscii(instanceId);
}

std::string jsonEscape(const std::string &value) {
  std::string output;
  for (char character : value) {
    if (character == '\\' || character == '"') output.push_back('\\');
    if (character == '\n') {
      output.append("\\n");
      continue;
    }
    output.push_back(character);
  }
  return output;
}

std::string recordJson(const InstanceRecord &record) {
  std::string json = "{\"protocol_version\":1,\"server_pid\":" +
      std::to_string(record.serverPid) + ",\"helper_pid\":" +
      std::to_string(record.helperPid);
  if (record.helperCreationTime != 0) {
    json.append(",\"helper_creation_time\":\"");
    json.append(std::to_string(record.helperCreationTime));
    json.push_back('"');
  }
  json.append(",\"instance_id\":\"");
  json.append(record.instanceId);
  json.append("\",\"endpoint\":\"");
  json.append(jsonEscape(record.endpoint));
  json.append("\"}");
  return json;
}

std::wstring recordFileName(const InstanceRecord &record) {
  return L"server-" + std::to_wstring(record.serverPid) + L"-" +
         widenAscii(record.instanceId) + L".record";
}

std::string recordContents(const InstanceRecord &record) {
  std::string contents = "protocol_version=1\nserver_pid=" + std::to_string(record.serverPid) +
      "\nhelper_pid=" + std::to_string(record.helperPid);
  if (record.helperCreationTime != 0) {
    contents.append("\nhelper_creation_time=");
    contents.append(std::to_string(record.helperCreationTime));
  }
  contents.append("\ninstance_id=");
  contents.append(record.instanceId);
  contents.append("\nendpoint=");
  contents.append(record.endpoint);
  contents.push_back('\n');
  return contents;
}

bool createSecureRecordFile(const std::wstring &path, SecurityContext &security,
                            const std::string &contents) {
  HANDLE raw = CreateFileW(path.c_str(), GENERIC_WRITE | READ_CONTROL,
      0, &security.attributes, CREATE_NEW,
      FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_OPEN_REPARSE_POINT,
      nullptr);
  if (raw == INVALID_HANDLE_VALUE) return false;
  UniqueHandle file(raw);
  bool valid = verifyFileHandle(file.get(), security, false);
  DWORD written = 0;
  valid = valid && WriteFile(file.get(), contents.data(), static_cast<DWORD>(contents.size()),
                             &written, nullptr) != FALSE &&
          static_cast<size_t>(written) == contents.size() && FlushFileBuffers(file.get()) != FALSE;
  file.reset();
  if (!valid) DeleteFileW(path.c_str());
  return valid;
}

bool publishRecord(const std::wstring &directory, SecurityContext &security,
                   const InstanceRecord &record, std::wstring &recordPath) {
  const std::wstring filename = recordFileName(record);
  recordPath = directory + L"\\" + filename;
  const std::wstring temporary = directory + L"\\.pending-" +
      std::to_wstring(GetCurrentProcessId()) + L"-" +
      std::to_wstring(GetTickCount64()) + L".record";
  const std::string contents = recordContents(record);
  if (!createSecureRecordFile(temporary, security, contents)) return false;
  if (!MoveFileExW(temporary.c_str(), recordPath.c_str(), MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(temporary.c_str());
    return false;
  }
  HANDLE file = CreateFileW(recordPath.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  const bool valid = verifyFileHandle(file, security, false);
  CloseHandle(file);
  return valid;
}

#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
// Replaces a protected discovery record from the helper's own security context.
bool replaceRecordForTest(const std::wstring &path, SecurityContext &security,
                          const InstanceRecord &record) {
  const std::wstring replacement = path + L".pending-" +
      std::to_wstring(GetCurrentProcessId()) + L"-" +
      std::to_wstring(GetTickCount64());
  if (!createSecureRecordFile(replacement, security, recordContents(record))) return false;
  if (!MoveFileExW(replacement.c_str(), path.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(replacement.c_str());
    return false;
  }
  return true;
}
#endif

bool readSecureRecordFile(const std::wstring &path, const SecurityContext &security,
                          std::string &contents) {
  HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (raw == INVALID_HANDLE_VALUE) return false;
  UniqueHandle file(raw);
  if (!verifyFileHandle(file.get(), security, false)) return false;
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 || size.QuadPart > 4096) return false;
  contents.resize(static_cast<size_t>(size.QuadPart));
  DWORD read = 0;
  return ReadFile(file.get(), contents.data(), static_cast<DWORD>(contents.size()), &read,
                  nullptr) != FALSE && static_cast<size_t>(read) == contents.size();
}

bool parseRecordContents(const std::string &contents, InstanceRecord &record) {
  const std::string prefix = "protocol_version=1\nserver_pid=";
  if (contents.rfind(prefix, 0) != 0) return false;
  size_t cursor = prefix.size();
  auto readLine = [&contents, &cursor](std::string &value) -> bool {
    const size_t end = contents.find('\n', cursor);
    if (end == std::string::npos) return false;
    value = contents.substr(cursor, end - cursor);
    cursor = end + 1;
    return true;
  };
  std::string serverPid;
  std::string helperPid;
  std::string helperCreationTime;
  std::string instanceId;
  std::string endpoint;
  if (!readLine(serverPid) || serverPid.empty() ||
      contents.compare(cursor, 11, "helper_pid=") != 0) return false;
  cursor += 11;
  if (!readLine(helperPid) || helperPid.empty()) return false;
  if (contents.compare(cursor, 21, "helper_creation_time=") == 0) {
    cursor += 21;
    if (!readLine(helperCreationTime) || helperCreationTime.empty() ||
        helperCreationTime.size() > 20 || helperCreationTime[0] == '0') return false;
    ULONGLONG parsedCreation = 0;
    constexpr ULONGLONG maximumCreationTime = ~static_cast<ULONGLONG>(0);
    for (const char character : helperCreationTime) {
      if (character < '0' || character > '9') return false;
      const ULONGLONG digit = static_cast<ULONGLONG>(character - '0');
      if (parsedCreation > (maximumCreationTime - digit) / 10) return false;
      parsedCreation = parsedCreation * 10 + digit;
    }
    if (parsedCreation == 0) return false;
    record.helperCreationTime = parsedCreation;
  }
  if (contents.compare(cursor, 12, "instance_id=") != 0) return false;
  cursor += 12;
  if (!readLine(instanceId) || !isValidUuid(instanceId) ||
      contents.compare(cursor, 9, "endpoint=") != 0) return false;
  cursor += 9;
  if (!readLine(endpoint) || cursor != contents.size()) return false;
  try {
    size_t serverDigits = 0;
    size_t helperDigits = 0;
    const unsigned long parsedServer = std::stoul(serverPid, &serverDigits);
    const unsigned long parsedHelper = std::stoul(helperPid, &helperDigits);
    if (parsedServer == 0 || parsedServer > MAXDWORD || parsedHelper == 0 || parsedHelper > MAXDWORD) return false;
    if (serverDigits != serverPid.size() || helperDigits != helperPid.size()) return false;
    record.serverPid = static_cast<DWORD>(parsedServer);
    record.helperPid = static_cast<DWORD>(parsedHelper);
  } catch (...) {
    return false;
  }
  record.instanceId = instanceId;
  record.endpoint = endpoint;
  return endpoint == narrowAscii(pipeName(record.serverPid, record.instanceId));
}

bool readRecord(const std::wstring &path, const SecurityContext &security,
                InstanceRecord &record) {
  std::string contents;
  return readSecureRecordFile(path, security, contents) && parseRecordContents(contents, record);
}

// Validates every discovery file before returning any endpoints to the caller.
bool enumerateRecords(const std::wstring &directory, const SecurityContext &security,
                      std::vector<InstanceRecord> &records) {
  const std::wstring pattern = directory + L"\\server-*.record";
  WIN32_FIND_DATAW data{};
  HANDLE find = FindFirstFileW(pattern.c_str(), &data);
  if (find == INVALID_HANDLE_VALUE) {
    return GetLastError() == ERROR_FILE_NOT_FOUND;
  }
  bool valid = true;
  do {
    if ((data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
      valid = false;
      break;
    }
    InstanceRecord record{};
    const std::wstring recordPath = directory + L"\\" + data.cFileName;
    if (!readRecord(recordPath, security, record)) {
      valid = false;
      break;
    }
    const std::wstring expectedName = recordFileName(record);
    if (_wcsicmp(expectedName.c_str(), data.cFileName) != 0) {
      valid = false;
      break;
    }
    records.push_back(std::move(record));
  } while (FindNextFileW(find, &data));
  const DWORD lastError = GetLastError();
  FindClose(find);
  return valid && lastError == ERROR_NO_MORE_FILES;
}

bool removeRecordIfSame(const std::wstring &path, const SecurityContext &security,
                        const InstanceRecord &expected) {
  const DWORD attributes = GetFileAttributesW(path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    const DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
  }
  InstanceRecord current{};
  if (!readRecord(path, security, current)) return false;
  if (current.serverPid != expected.serverPid || current.helperPid != expected.helperPid ||
      current.helperCreationTime != expected.helperCreationTime ||
      current.instanceId != expected.instanceId || current.endpoint != expected.endpoint) return true;
  return DeleteFileW(path.c_str()) != FALSE || GetLastError() == ERROR_FILE_NOT_FOUND;
}

bool readAllControlLine(HANDLE input, HANDLE parentProcess, std::string &line) {
  line.clear();
  const ULONGLONG deadline = GetTickCount64() + kControlLineTimeoutMs;
  while (GetTickCount64() < deadline) {
    if (WaitForSingleObject(parentProcess, 0) == WAIT_OBJECT_0) return false;
    DWORD available = 0;
    if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) return false;
    if (available == 0) {
      Sleep(20);
      continue;
    }
    BYTE character = 0;
    DWORD read = 0;
    if (!ReadFile(input, &character, 1, &read, nullptr) || read == 0) return false;
    if (character == '\n') return true;
    if (line.size() >= kMaximumControlLineBytes) return false;
    line.push_back(static_cast<char>(character));
  }
  return false;
}

IoWaitResult waitForIo(HANDLE event, HANDLE parentProcess, DWORD timeoutMs) {
  HANDLE handles[2] = {event, parentProcess};
  const DWORD count = parentProcess == nullptr ? 1 : 2;
  const DWORD result = WaitForMultipleObjects(count, handles, FALSE, timeoutMs);
  if (result == WAIT_OBJECT_0) return IoWaitResult::kCompleted;
  if (parentProcess != nullptr && result == WAIT_OBJECT_0 + 1) return IoWaitResult::kParentExited;
  if (result == WAIT_TIMEOUT) return IoWaitResult::kTimedOut;
  return IoWaitResult::kFailed;
}

DWORD remainingMilliseconds(ULONGLONG deadline) {
  const ULONGLONG now = GetTickCount64();
  if (now >= deadline) return 0;
  return static_cast<DWORD>(std::min<ULONGLONG>(deadline - now, MAXDWORD));
}

bool finishOverlapped(HANDLE pipe, OVERLAPPED &operation, HANDLE parentProcess,
                      DWORD &transferred, ULONGLONG deadline) {
  const DWORD remaining = remainingMilliseconds(deadline);
  const IoWaitResult wait = remaining == 0 ? IoWaitResult::kTimedOut
      : waitForIo(operation.hEvent, parentProcess, remaining);
  if (wait != IoWaitResult::kCompleted) {
    CancelIoEx(pipe, &operation);
    WaitForSingleObject(operation.hEvent, INFINITE);
    SetLastError(wait == IoWaitResult::kParentExited ? ERROR_OPERATION_ABORTED
        : wait == IoWaitResult::kTimedOut ? ERROR_SEM_TIMEOUT : ERROR_GEN_FAILURE);
    return false;
  }
  return GetOverlappedResult(pipe, &operation, &transferred, FALSE) != FALSE;
}

bool readPipeMessage(HANDLE pipe, HANDLE parentProcess, std::vector<BYTE> &message,
                     ULONGLONG deadline) {
  BYTE buffer[kMaximumInputBytes + 1];
  DWORD read = 0;
  OVERLAPPED operation{};
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) return false;
  operation.hEvent = event.get();
  BOOL succeeded = ReadFile(pipe, buffer, sizeof(buffer), &read, &operation);
  if (!succeeded && GetLastError() == ERROR_IO_PENDING) {
    if (!finishOverlapped(pipe, operation, parentProcess, read, deadline)) return false;
    succeeded = TRUE;
  }
  if (!succeeded || read > kMaximumInputBytes) return false;
  message.assign(buffer, buffer + read);
  return hasValidFrame(message);
}

bool writePipeMessage(HANDLE pipe, const std::vector<BYTE> &message,
                      HANDLE parentProcess, ULONGLONG deadline) {
  if (!hasValidFrame(message)) return false;
  DWORD written = 0;
  OVERLAPPED operation{};
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) return false;
  operation.hEvent = event.get();
  BOOL succeeded = WriteFile(pipe, message.data(), static_cast<DWORD>(message.size()),
                             &written, &operation);
  if (!succeeded && GetLastError() == ERROR_IO_PENDING) {
    if (!finishOverlapped(pipe, operation, parentProcess, written, deadline)) return false;
  } else if (!succeeded) {
    return false;
  }
  return written == message.size();
}

enum class ConnectResult { kConnected, kShutdown, kParentGone, kFailed };

ConnectResult connectPipe(HANDLE pipe, HANDLE parentProcess, HANDLE shutdownEvent) {
  OVERLAPPED operation{};
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) return ConnectResult::kFailed;
  operation.hEvent = event.get();
  const BOOL connected = ConnectNamedPipe(pipe, &operation);
  if (connected) return ConnectResult::kConnected;
  const DWORD error = GetLastError();
  if (error == ERROR_PIPE_CONNECTED) return ConnectResult::kConnected;
  if (error != ERROR_IO_PENDING) return ConnectResult::kFailed;

  HANDLE handles[3] = {operation.hEvent, parentProcess, shutdownEvent};
  for (;;) {
    const DWORD result = WaitForMultipleObjects(3, handles, FALSE, 50);
    if (result == WAIT_OBJECT_0) {
      DWORD transferred = 0;
      return GetOverlappedResult(pipe, &operation, &transferred, FALSE) != FALSE
          ? ConnectResult::kConnected : ConnectResult::kFailed;
    }
    if (result == WAIT_OBJECT_0 + 1) {
      CancelIoEx(pipe, &operation);
      WaitForSingleObject(operation.hEvent, INFINITE);
      return ConnectResult::kParentGone;
    }
    if (result == WAIT_OBJECT_0 + 2) {
      CancelIoEx(pipe, &operation);
      WaitForSingleObject(operation.hEvent, INFINITE);
      return ConnectResult::kShutdown;
    }
    if (result != WAIT_TIMEOUT) {
      CancelIoEx(pipe, &operation);
      WaitForSingleObject(operation.hEvent, INFINITE);
      return ConnectResult::kFailed;
    }
  }
}

// Creates one local-only pipe instance with the helper user's protected ACL.
// The serve loop opens each replacement while another helper-owned instance
// remains open, so an unprivileged process outside that SID cannot claim the
// name between instances.
HANDLE createServerPipe(const std::wstring &name, SecurityContext &security,
                        bool firstInstance
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
                        , DWORD *createdModeForTest = nullptr
#endif
                        ) {
  DWORD flags = FILE_FLAG_OVERLAPPED;
  if (firstInstance) flags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
  const DWORD pipeMode =
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  if (createdModeForTest) *createdModeForTest = pipeMode;
#endif
  return CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | flags, pipeMode,
      kMaximumPipeInstances, kPipeBufferBytes, kPipeBufferBytes, kConnectionTimeoutMs,
      &security.attributes);
}

enum class ControlResult { kResponse, kAbort, kShutdown, kParentGone };

struct PendingConnection {
  std::condition_variable changed;
  bool ready = false;
  bool aborted = false;
  std::vector<BYTE> response;
};

struct ControlHub {
  std::mutex mutex;
  std::condition_variable workersChanged;
  std::unordered_map<std::string, std::shared_ptr<PendingConnection>> pending;
  size_t activeWorkers = 0;
  std::atomic<bool> shuttingDown{false};
  HANDLE shutdownEvent = nullptr;
};

bool isValidConnectionId(const std::string &value) {
  const size_t separator = value.find('-');
  if (separator == std::string::npos || separator == 0 || separator + 1 >= value.size() ||
      value.find('-', separator + 1) != std::string::npos) return false;
  for (size_t index = 0; index < value.size(); ++index) {
    if (index == separator) continue;
    if (value[index] < '0' || value[index] > '9') return false;
  }
  return value[0] != '0' && value[separator + 1] != '0';
}

bool hasJsonStringField(const std::string &json, const char *name, const char *expected) {
  const std::string key = std::string("\"") + name + "\"";
  const size_t keyPosition = json.find(key);
  if (keyPosition == std::string::npos) return false;
  size_t cursor = keyPosition + key.size();
  const auto skipWhitespace = [&json](size_t &position) {
    while (position < json.size() &&
           (json[position] == ' ' || json[position] == '\t' ||
            json[position] == '\r' || json[position] == '\n')) ++position;
  };
  skipWhitespace(cursor);
  if (cursor >= json.size() || json[cursor++] != ':') return false;
  skipWhitespace(cursor);
  const std::string value = std::string("\"") + expected + "\"";
  if (json.compare(cursor, value.size(), value) != 0) return false;
  cursor += value.size();
  skipWhitespace(cursor);
  return cursor == json.size() || json[cursor] == ',' || json[cursor] == '}';
}

bool isReloadRequest(const std::vector<BYTE> &request) {
  if (request.size() < 4) return false;
  const std::string json(reinterpret_cast<const char *>(request.data() + 4), request.size() - 4);
  return hasJsonStringField(json, "operation", "reload");
}

std::string nextConnectionId() {
  const ULONGLONG sequence = g_connectionSequence.fetch_add(1);
  return std::to_string(GetCurrentProcessId()) + "-" + std::to_string(sequence);
}

void signalShutdown(ControlHub &hub) {
  hub.shuttingDown.store(true);
  if (hub.shutdownEvent != nullptr) SetEvent(hub.shutdownEvent);
  std::lock_guard<std::mutex> lock(hub.mutex);
  for (auto &entry : hub.pending) {
    entry.second->aborted = true;
    entry.second->changed.notify_all();
  }
  hub.pending.clear();
}

void dispatchControlLine(const std::string &line, ControlHub &hub) {
  if (line == "SHUTDOWN") {
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
    if (wcscmp(testFault(), L"hold-shutdown") == 0) Sleep(INFINITE);
#endif
    signalShutdown(hub);
    return;
  }

  constexpr char abortPrefix[] = "ABORT\t";
  if (line.rfind(abortPrefix, 0) == 0) {
    const std::string connectionId = line.substr(sizeof(abortPrefix) - 1);
    if (!isValidConnectionId(connectionId)) {
      signalShutdown(hub);
      return;
    }
    std::lock_guard<std::mutex> lock(hub.mutex);
    const auto found = hub.pending.find(connectionId);
    if (found != hub.pending.end()) {
      found->second->aborted = true;
      found->second->changed.notify_all();
      hub.pending.erase(found);
    }
    return;
  }

  constexpr char responsePrefix[] = "RESPONSE\t";
  if (line.rfind(responsePrefix, 0) == 0) {
    const size_t separator = line.find('\t', sizeof(responsePrefix) - 1);
    if (separator == std::string::npos) {
      signalShutdown(hub);
      return;
    }
    const std::string connectionId = line.substr(sizeof(responsePrefix) - 1,
                                                  separator - (sizeof(responsePrefix) - 1));
    std::vector<BYTE> response;
    if (!isValidConnectionId(connectionId) ||
        !decodeBase64(line.substr(separator + 1), response) || !hasValidFrame(response)) {
      signalShutdown(hub);
      return;
    }
    std::lock_guard<std::mutex> lock(hub.mutex);
    const auto found = hub.pending.find(connectionId);
    if (found != hub.pending.end()) {
      found->second->response = std::move(response);
      found->second->ready = true;
      found->second->changed.notify_all();
      hub.pending.erase(found);
    }
    // Unknown IDs are late responses for connections that already ended.
    return;
  }

  signalShutdown(hub);
}

void readControlMessages(HANDLE parentProcess, ControlHub &hub) {
  const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  while (!hub.shuttingDown.load()) {
    if (WaitForSingleObject(parentProcess, 0) == WAIT_OBJECT_0) break;
    DWORD available = 0;
    if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) break;
    if (available == 0) {
      Sleep(20);
      continue;
    }
    std::string line;
    if (!readAllControlLine(input, parentProcess, line)) break;
    dispatchControlLine(line, hub);
  }
  signalShutdown(hub);
}

void removePending(ControlHub &hub, const std::string &connectionId,
                   const std::shared_ptr<PendingConnection> &pending) {
  std::lock_guard<std::mutex> lock(hub.mutex);
  const auto found = hub.pending.find(connectionId);
  if (found != hub.pending.end() && found->second == pending) hub.pending.erase(found);
}

ControlResult waitForControlResponse(
    HANDLE parentProcess, HANDLE clientProcess, ControlHub &hub,
    const std::string &connectionId,
    const std::shared_ptr<PendingConnection> &pending,
    std::vector<BYTE> &response, ULONGLONG deadline) {
  std::unique_lock<std::mutex> lock(hub.mutex);
  for (;;) {
    if (hub.shuttingDown.load()) return ControlResult::kShutdown;
    if (pending->ready) {
      response = std::move(pending->response);
      return ControlResult::kResponse;
    }
    if (pending->aborted) return ControlResult::kAbort;
    lock.unlock();

    if (WaitForSingleObject(parentProcess, 0) == WAIT_OBJECT_0) {
      signalShutdown(hub);
      return ControlResult::kParentGone;
    }
    if (hub.shuttingDown.load()) return ControlResult::kShutdown;
    if (clientProcess != nullptr && WaitForSingleObject(clientProcess, 0) == WAIT_OBJECT_0) {
      writeStdout("ABORT\t" + connectionId + "\n");
      removePending(hub, connectionId, pending);
      return ControlResult::kAbort;
    }
    if (remainingMilliseconds(deadline) == 0) {
      writeStdout("ABORT\t" + connectionId + "\n");
      removePending(hub, connectionId, pending);
      return ControlResult::kAbort;
    }

    lock.lock();
    pending->changed.wait_for(lock, std::chrono::milliseconds(20));
  }
}

ControlResult handleServerConnection(HANDLE pipe, HANDLE parentProcess, ControlHub &hub) {
  std::vector<BYTE> request;
  const ULONGLONG requestDeadline = GetTickCount64() + kConnectionTimeoutMs;
  if (!readPipeMessage(pipe, parentProcess, request, requestDeadline)) {
    return WaitForSingleObject(parentProcess, 0) == WAIT_OBJECT_0
        ? ControlResult::kParentGone : ControlResult::kAbort;
  }

  DWORD clientPid = 0;
  UniqueHandle clientProcess;
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  const bool monitorClient = wcscmp(testFault(), L"unmonitored-client") != 0;
#else
  constexpr bool monitorClient = true;
#endif
  if (monitorClient && GetNamedPipeClientProcessId(pipe, &clientPid) && clientPid != 0) {
    HANDLE rawClient = OpenProcess(SYNCHRONIZE, FALSE, clientPid);
    if (rawClient != nullptr) clientProcess.reset(rawClient);
  }

  const std::string connectionId = nextConnectionId();
  auto pending = std::make_shared<PendingConnection>();
  {
    std::lock_guard<std::mutex> lock(hub.mutex);
    if (hub.shuttingDown.load() || !hub.pending.emplace(connectionId, pending).second) {
      return ControlResult::kShutdown;
    }
  }

  const std::string line = "REQUEST\t" + connectionId + "\t" +
      encodeBase64(request.data(), request.size()) + "\n";
  if (!writeStdout(line)) {
    removePending(hub, connectionId, pending);
    return ControlResult::kParentGone;
  }

  std::vector<BYTE> response;
  const DWORD acknowledgmentTimeout = isReloadRequest(request)
      ? kReloadAcknowledgmentTimeoutMs : kProbeTimeoutMs;
  const ULONGLONG acknowledgmentDeadline = GetTickCount64() + acknowledgmentTimeout;
  const ControlResult result = waitForControlResponse(
      parentProcess, clientProcess.get(), hub, connectionId, pending,
      response, acknowledgmentDeadline);
  if (result != ControlResult::kResponse) return result;
  if (!writePipeMessage(pipe, response, parentProcess, acknowledgmentDeadline)) {
    writeStdout("ABORT\t" + connectionId + "\n");
    return ControlResult::kAbort;
  }
  return ControlResult::kResponse;
}

void workerFinished(ControlHub &hub) {
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  bool workersClosed = false;
#endif
  {
    std::lock_guard<std::mutex> lock(hub.mutex);
    if (hub.activeWorkers > 0) --hub.activeWorkers;
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
    workersClosed = hub.activeWorkers == 0;
#endif
    hub.workersChanged.notify_all();
  }
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  if (workersClosed && wcscmp(testFault(), L"hold-at-connection-capacity") == 0) {
    writeTestMarker(L"GPT_REPO_ADMIN_TEST_WORKERS_CLOSED");
  }
#endif
}

void waitForWorkers(ControlHub &hub) {
  std::unique_lock<std::mutex> lock(hub.mutex);
  hub.workersChanged.wait(lock, [&hub] { return hub.activeWorkers == 0; });
}

// The parent must accept this endpoint identity before discovery is published.
bool writeReady(const InstanceRecord &record) {
  const std::string line = "READY\t" + recordJson(record) + "\n";
  return writeStdout(line);
}

// Confirms the endpoint with its parent before publishing discovery or relaying requests.
int serve(DWORD serverPid, const std::string &instanceId) {
  SecurityContext security;
  if (!createSecurityContext(security)) return 20;
  HANDLE parentRaw = OpenProcess(SYNCHRONIZE, FALSE, serverPid);
  if (parentRaw == nullptr) return 21;
  UniqueHandle parentProcess(parentRaw);
  if (WaitForSingleObject(parentProcess.get(), 0) == WAIT_OBJECT_0) return 22;

  std::wstring directory;
  bool directoryExists = false;
  int directorySetupFailure = 23;
  if (!getAdminDirectory(security, true, directory, directoryExists, &directorySetupFailure) ||
      !directoryExists) return directorySetupFailure;
  const std::wstring name = pipeName(serverPid, instanceId);
  HANDLE firstPipe = createServerPipe(name, security, true);
  if (firstPipe == INVALID_HANDLE_VALUE) return 24;
  UniqueHandle pipe(firstPipe);

  InstanceRecord record{};
  record.serverPid = serverPid;
  record.helperPid = GetCurrentProcessId();
  if (!getProcessCreationTime(GetCurrentProcess(), record.helperCreationTime)) return 20;
  record.instanceId = instanceId;
  record.endpoint = narrowAscii(name);
  std::wstring recordPath;
  if (record.endpoint.empty()) return 25;
  UniqueHandle shutdownEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!shutdownEvent) return 27;

  if (!writeReady(record)) return 26;
  std::string startupAcknowledgment;
  const std::string expectedAcknowledgment = "READY_ACCEPTED\t" + instanceId;
  if (!readAllControlLine(GetStdHandle(STD_INPUT_HANDLE), parentProcess.get(), startupAcknowledgment) ||
      startupAcknowledgment != expectedAcknowledgment) return 27;
  if (!publishRecord(directory, security, record, recordPath)) return 25;

  ControlHub hub;
  hub.shutdownEvent = shutdownEvent.get();
  std::thread controlReader;
  try {
    controlReader = std::thread(readControlMessages, parentProcess.get(), std::ref(hub));
  } catch (...) {
    removeRecordIfSame(recordPath, security, record);
    return 27;
  }
  int exitCode = 0;
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  bool capacityPauseUsed = false;
#endif
  if (!writeStdout("PUBLISHED\t" + instanceId + "\n")) {
    exitCode = 26;
    signalShutdown(hub);
  }
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  if (wcscmp(testFault(), L"break-control-output") == 0) {
    Sleep(100);
    CloseHandle(GetStdHandle(STD_OUTPUT_HANDLE));
  }
  if (wcscmp(testFault(), L"break-control-input") == 0) {
    Sleep(100);
    CloseHandle(GetStdHandle(STD_INPUT_HANDLE));
  }
#endif

  while (!hub.shuttingDown.load()) {
    size_t activeWorkers = 0;
    {
      std::lock_guard<std::mutex> lock(hub.mutex);
      activeWorkers = hub.activeWorkers;
    }
    if (!pipe) {
      pipe.reset(createServerPipe(name, security, false));
      if (!pipe) {
        exitCode = 29;
        break;
      }
    }
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
    if (activeWorkers >= kMaximumConnections && !capacityPauseUsed &&
        wcscmp(testFault(), L"hold-at-connection-capacity") == 0) {
      capacityPauseUsed = true;
      if (!writeTestMarker(L"GPT_REPO_ADMIN_TEST_CAPACITY_REACHED")) {
        exitCode = 29;
        break;
      }
      while (!hub.shuttingDown.load() &&
             !testMarkerExists(L"GPT_REPO_ADMIN_TEST_RELEASE_CAPACITY")) {
        Sleep(10);
      }
    }
#endif
    if (activeWorkers >= kMaximumConnections) {
      Sleep(20);
      continue;
    }

    const ConnectResult connection = connectPipe(
        pipe.get(), parentProcess.get(), shutdownEvent.get());
    if (connection == ConnectResult::kShutdown || connection == ConnectResult::kParentGone) break;
    if (connection != ConnectResult::kConnected) {
      exitCode = 28;
      break;
    }

    UniqueHandle connectedPipe = std::move(pipe);
    pipe.reset(createServerPipe(name, security, false));
    if (!pipe) {
      exitCode = 29;
      if (connectedPipe) DisconnectNamedPipe(connectedPipe.get());
      pipe = std::move(connectedPipe);
      break;
    }
    {
      std::lock_guard<std::mutex> lock(hub.mutex);
      ++hub.activeWorkers;
    }
    try {
      std::thread([connectedPipe = std::move(connectedPipe), parent = parentProcess.get(),
                   &hub]() mutable {
        const ControlResult result = handleServerConnection(connectedPipe.get(), parent, hub);
        if (connectedPipe) DisconnectNamedPipe(connectedPipe.get());
        connectedPipe.reset();
        if (result == ControlResult::kParentGone) signalShutdown(hub);
        workerFinished(hub);
      }).detach();
    } catch (...) {
      if (connectedPipe) DisconnectNamedPipe(connectedPipe.get());
      connectedPipe.reset();
      workerFinished(hub);
    }
  }

  pipe.reset();
  signalShutdown(hub);
  waitForWorkers(hub);
  if (controlReader.joinable()) controlReader.join();
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  if (wcscmp(testFault(), L"replace-record-before-cleanup") == 0) {
    InstanceRecord replacement = record;
    ++replacement.helperCreationTime;
    if (!replaceRecordForTest(recordPath, security, replacement)) exitCode = 31;
  }
#endif
  if (!removeRecordIfSame(recordPath, security, record) && exitCode == 0) exitCode = 30;
  return exitCode;
}

bool validLocalPipeName(const std::wstring &endpoint) {
  constexpr wchar_t prefix[] = L"\\\\.\\pipe\\gpt-repo-mcp-";
  if (endpoint.rfind(prefix, 0) != 0) return false;
  const std::wstring rest = endpoint.substr(sizeof(prefix) / sizeof(prefix[0]) - 1);
  const size_t separator = rest.find(L'-');
  if (separator == std::wstring::npos || separator == 0) return false;
  DWORD pid = 0;
  if (!parsePositivePid(rest.substr(0, separator).c_str(), pid)) return false;
  const std::string uuid = narrowAscii(rest.substr(separator + 1));
  return isValidUuid(uuid) && endpoint == pipeName(pid, uuid);
}

#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
const wchar_t *testFault();
#endif

bool openClientPipe(const std::wstring &endpoint, HANDLE &pipe,
                    ULONGLONG deadline, DWORD &errorCode) {
  DWORD access = READ_CONTROL | FILE_READ_DATA | FILE_WRITE_DATA |
                 FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  // This fault changes the ACL after verification; production clients never request WRITE_DAC.
  if (wcscmp(testFault(), L"pause-and-change-pipe-dacl") == 0) access |= WRITE_DAC;
#endif
  for (;;) {
    const DWORD remaining = remainingMilliseconds(deadline);
    if (remaining == 0) {
      errorCode = ERROR_SEM_TIMEOUT;
      return false;
    }
    HANDLE raw = CreateFileW(endpoint.c_str(), access, 0, nullptr, OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT |
                                 SECURITY_IDENTIFICATION | SECURITY_EFFECTIVE_ONLY,
                             nullptr);
    if (raw != INVALID_HANDLE_VALUE) {
      pipe = raw;
      DWORD mode = PIPE_READMODE_MESSAGE;
      if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) {
        errorCode = GetLastError();
        CloseHandle(pipe);
        pipe = INVALID_HANDLE_VALUE;
        return false;
      }
      return true;
    }
    const DWORD error = GetLastError();
    errorCode = error;
    if (error == ERROR_PIPE_BUSY) {
      if (WaitNamedPipeW(endpoint.c_str(), remaining)) continue;
      errorCode = GetLastError();
      if (errorCode != ERROR_FILE_NOT_FOUND) return false;
    } else if (error != ERROR_FILE_NOT_FOUND) {
      return false;
    }
    const DWORD retryDelay = remainingMilliseconds(deadline);
    if (retryDelay == 0) {
      errorCode = ERROR_SEM_TIMEOUT;
      return false;
    }
    Sleep(std::min<DWORD>(10, retryDelay));
  }
}

enum class ClientWriteResult { kWritten, kNotDispatched, kIndeterminate };

ClientWriteResult clientWrite(HANDLE pipe, const std::vector<BYTE> &request,
                              DWORD &written, DWORD &errorCode,
                              ULONGLONG deadline) {
  OVERLAPPED operation{};
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) {
    errorCode = GetLastError();
    return ClientWriteResult::kNotDispatched;
  }
  operation.hEvent = event.get();
  if (remainingMilliseconds(deadline) == 0) {
    errorCode = ERROR_SEM_TIMEOUT;
    return ClientWriteResult::kNotDispatched;
  }
  BOOL succeeded = WriteFile(pipe, request.data(), static_cast<DWORD>(request.size()),
                             &written, &operation);
  if (!succeeded && GetLastError() == ERROR_IO_PENDING) {
    if (!finishOverlapped(pipe, operation, nullptr, written, deadline)) {
      return ClientWriteResult::kIndeterminate;
    }
  } else if (!succeeded) {
    return ClientWriteResult::kIndeterminate;
  }
  if (written != request.size()) return ClientWriteResult::kIndeterminate;
  errorCode = ERROR_SUCCESS;
  return ClientWriteResult::kWritten;
}

#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
const wchar_t *testFault() {
  static thread_local wchar_t value[64]{};
  const DWORD length = GetEnvironmentVariableW(L"GPT_REPO_ADMIN_TEST_FAULT", value,
                                                static_cast<DWORD>(std::size(value)));
  if (length == 0 || length >= std::size(value)) return L"";
  return value;
}

bool testPathFromEnvironment(const wchar_t *name, std::wstring &path) {
  wchar_t value[MAX_PATH]{};
  const DWORD length = GetEnvironmentVariableW(name, value, static_cast<DWORD>(std::size(value)));
  if (length == 0 || length >= std::size(value)) return false;
  path.assign(value, length);
  return true;
}

bool writeTestMarker(const wchar_t *environmentName) {
  std::wstring path;
  if (!testPathFromEnvironment(environmentName, path)) return false;
  UniqueHandle marker(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                  nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!marker) return false;
  constexpr char contents[] = "ready\n";
  DWORD written = 0;
  return WriteFile(marker.get(), contents, static_cast<DWORD>(sizeof(contents) - 1),
                   &written, nullptr) != FALSE && written == sizeof(contents) - 1 &&
      FlushFileBuffers(marker.get()) != FALSE;
}

bool testMarkerExists(const wchar_t *environmentName) {
  std::wstring path;
  if (!testPathFromEnvironment(environmentName, path)) return false;
  const DWORD attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// Adds a test ACE through the connected handle to make the dispatch-time ACL check reject it.
bool addTestWorldReadAceToPipe(HANDLE pipe, const SecurityContext &security) {
  BYTE worldSidBuffer[SECURITY_MAX_SID_SIZE]{};
  DWORD worldSidSize = sizeof(worldSidBuffer);
  if (!CreateWellKnownSid(WinWorldSid, nullptr, worldSidBuffer, &worldSidSize)) return false;

  PACL currentDacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const DWORD queryError = GetSecurityInfo(pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                                           nullptr, nullptr, &currentDacl, nullptr, &descriptor);
  if (queryError != ERROR_SUCCESS) {
    if (descriptor != nullptr) LocalFree(descriptor);
    return false;
  }

  EXPLICIT_ACCESSW entry{};
  entry.grfAccessPermissions = FILE_READ_DATA;
  entry.grfAccessMode = GRANT_ACCESS;
  entry.grfInheritance = NO_INHERITANCE;
  entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entry.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  entry.Trustee.ptstrName = reinterpret_cast<LPWSTR>(worldSidBuffer);
  PACL changedDacl = nullptr;
  const DWORD aclError = SetEntriesInAclW(1, &entry, currentDacl, &changedDacl);
  DWORD setError = aclError;
  if (aclError == ERROR_SUCCESS) {
    setError = SetSecurityInfo(pipe, SE_KERNEL_OBJECT,
                               DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                               nullptr, nullptr, changedDacl, nullptr);
  }
  if (changedDacl != nullptr) LocalFree(changedDacl);
  if (descriptor != nullptr) LocalFree(descriptor);
  return setError == ERROR_SUCCESS && !hasOwnerOnlyDacl(pipe, security, SE_KERNEL_OBJECT);
}
#endif

// Checks the connected pipe descriptor, then confirms the discovered helper is live.
bool verifyPipeOwnerAndHelperMetadata(HANDLE pipe, const SecurityContext &security,
                                     DWORD expectedHelperPid,
                                     ULONGLONG expectedCreationTime,
                                     UniqueHandle &verifiedHelperProcess,
                                     DWORD &errorCode) {
  if (!hasOwnerOnlyDacl(pipe, security, SE_KERNEL_OBJECT)) {
    errorCode = ERROR_ACCESS_DENIED;
    return false;
  }
  HANDLE rawProcess = OpenProcess(
      PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, expectedHelperPid);
  if (rawProcess == nullptr) {
    errorCode = GetLastError();
    return false;
  }
  verifiedHelperProcess.reset(rawProcess);
  ULONGLONG actualCreationTime = 0;
  if (!getProcessCreationTime(verifiedHelperProcess.get(), actualCreationTime)) {
    errorCode = GetLastError();
    return false;
  }
  if (actualCreationTime != expectedCreationTime) {
    errorCode = ERROR_ACCESS_DENIED;
    return false;
  }
  const DWORD processState = WaitForSingleObject(verifiedHelperProcess.get(), 0);
  if (processState != WAIT_TIMEOUT) {
    errorCode = processState == WAIT_FAILED ? GetLastError() : ERROR_ACCESS_DENIED;
    return false;
  }
  errorCode = ERROR_SUCCESS;
  return true;
}

// Rechecks the pipe descriptor and pinned helper process immediately before dispatch.
bool verifyPipeOwnerAndHelperBeforeDispatch(
    HANDLE pipe, const SecurityContext &security, DWORD expectedHelperPid,
    ULONGLONG expectedCreationTime, HANDLE verifiedHelperProcess,
    DWORD &errorCode) {
  if (!hasOwnerOnlyDacl(pipe, security, SE_KERNEL_OBJECT)) {
    errorCode = ERROR_ACCESS_DENIED;
    return false;
  }
  const DWORD actualHelperPid = GetProcessId(verifiedHelperProcess);
  if (actualHelperPid == 0) {
    errorCode = GetLastError();
    return false;
  }
  if (actualHelperPid != expectedHelperPid) {
    errorCode = ERROR_ACCESS_DENIED;
    return false;
  }
  ULONGLONG actualCreationTime = 0;
  if (!getProcessCreationTime(verifiedHelperProcess, actualCreationTime)) {
    errorCode = GetLastError();
    return false;
  }
  if (actualCreationTime != expectedCreationTime) {
    errorCode = ERROR_ACCESS_DENIED;
    return false;
  }
  const DWORD processState = WaitForSingleObject(verifiedHelperProcess, 0);
  if (processState != WAIT_TIMEOUT) {
    errorCode = processState == WAIT_FAILED ? GetLastError() : ERROR_ACCESS_DENIED;
    return false;
  }
  errorCode = ERROR_SUCCESS;
  return true;
}

int client(const std::wstring &endpoint, DWORD timeoutMs,
           DWORD expectedHelperPid, ULONGLONG expectedCreationTime) {
  // The caller supplies one operation budget for reload or status. Keep one
  // deadline across pipe connection, request write, and response read.
  const ULONGLONG operationDeadline = GetTickCount64() + timeoutMs;
  std::vector<BYTE> request;
  if (!validLocalPipeName(endpoint) ||
      !readAllInput(GetStdHandle(STD_INPUT_HANDLE), kMaximumInputBytes, request) ||
      !hasValidFrame(request)) {
    writeStdout("NOT_DISPATCHED\t0\n");
    return 31;
  }

  SecurityContext security;
  if (!createSecurityContext(security)) {
    DWORD error = GetLastError();
    if (error == ERROR_SUCCESS) error = ERROR_ACCESS_DENIED;
    writeStdout("NOT_DISPATCHED\t" + std::to_string(error) + "\n");
    return 34;
  }
  HANDLE rawPipe = INVALID_HANDLE_VALUE;
  DWORD openError = ERROR_SUCCESS;
  const ULONGLONG connectionDeadline = std::min<ULONGLONG>(
      operationDeadline, GetTickCount64() + kConnectionTimeoutMs);
  if (!openClientPipe(endpoint, rawPipe, connectionDeadline, openError)) {
    writeStdout("NOT_DISPATCHED\t" + std::to_string(openError) + "\n");
    return 34;
  }
  UniqueHandle pipe(rawPipe);
  UniqueHandle verifiedHelperProcess;
  DWORD verificationError = ERROR_SUCCESS;
  if (!verifyPipeOwnerAndHelperMetadata(
          pipe.get(), security, expectedHelperPid, expectedCreationTime,
          verifiedHelperProcess, verificationError)) {
    if (verificationError == ERROR_SUCCESS) verificationError = ERROR_ACCESS_DENIED;
    writeStdout("NOT_DISPATCHED\t" + std::to_string(verificationError) + "\n");
    return 34;
  }

#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  if (wcscmp(testFault(), L"before-write") == 0) {
    writeStdout("NOT_DISPATCHED\t0\n");
    return 32;
  }
  if (wcscmp(testFault(), L"silent-before-write") == 0) return 33;
  const bool pauseForDaclMutation =
      wcscmp(testFault(), L"pause-and-change-pipe-dacl") == 0;
  if (wcscmp(testFault(), L"pause-after-pipe-security-check") == 0 ||
      pauseForDaclMutation) {
    if (!writeStdout("VERIFIED\t" + std::to_string(operationDeadline) + "\n")) return 32;
    const ULONGLONG pauseDeadline = operationDeadline;
    while (GetTickCount64() < pauseDeadline &&
           !testMarkerExists(L"GPT_REPO_ADMIN_TEST_RELEASE_MARKER")) {
      Sleep(10);
    }
    if (!testMarkerExists(L"GPT_REPO_ADMIN_TEST_RELEASE_MARKER")) {
      writeStdout("NOT_DISPATCHED\t" + std::to_string(ERROR_SEM_TIMEOUT) + "\n");
      return 34;
    }
    if (pauseForDaclMutation) {
      if (!addTestWorldReadAceToPipe(pipe.get(), security)) {
        writeStdout("TEST_DACL_MUTATION_FAILED\n");
        return 32;
      }
      if (!writeStdout("DACL_CHANGED\n")) return 32;
    }
  }
  if (wcscmp(testFault(), L"expire-before-write") == 0) Sleep(timeoutMs + 50);
#endif

  if (remainingMilliseconds(operationDeadline) == 0) {
    writeStdout("NOT_DISPATCHED\t" + std::to_string(ERROR_SEM_TIMEOUT) + "\n");
    return 34;
  }
  if (!verifyPipeOwnerAndHelperBeforeDispatch(
          pipe.get(), security, expectedHelperPid, expectedCreationTime,
          verifiedHelperProcess.get(), verificationError)) {
    if (remainingMilliseconds(operationDeadline) == 0) {
      verificationError = ERROR_SEM_TIMEOUT;
    }
    if (verificationError == ERROR_SUCCESS) verificationError = ERROR_ACCESS_DENIED;
    writeStdout("NOT_DISPATCHED\t" + std::to_string(verificationError) + "\n");
    return 34;
  }

  DWORD written = 0;
  DWORD writeError = ERROR_SUCCESS;
  const ClientWriteResult writeResult = clientWrite(
      pipe.get(), request, written, writeError, operationDeadline);
  if (writeResult == ClientWriteResult::kNotDispatched) {
    writeStdout("NOT_DISPATCHED\t" + std::to_string(writeError) + "\n");
    return 34;
  }
  if (writeResult == ClientWriteResult::kIndeterminate) {
    writeStdout("INDETERMINATE\n");
    return 35;
  }

#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  if (wcscmp(testFault(), L"after-write") == 0 ||
      wcscmp(testFault(), L"lose-dispatch-notification") == 0) return 36;
#endif

  std::vector<BYTE> response;
  if (!readPipeMessage(pipe.get(), nullptr, response, operationDeadline)) {
    writeStdout("INDETERMINATE\n");
    return 37;
  }
  if (!writeStdout("RESPONSE\n") ||
      !writeStdoutBytes(response.data(), static_cast<DWORD>(response.size()))) return 38;
  return 0;
}

#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
// Compare matched remote-client controls with first and successor handles from
// the shared production factory. Keep the CreateNamedPipeW mode as the
// regression oracle because the public GetNamedPipeInfo reference omits this bit.
struct PipeModeObservation {
  bool succeeded = false;
  DWORD flags = 0;
  DWORD error = ERROR_SUCCESS;
};

void observePipeMode(HANDLE pipe, PipeModeObservation &observation) {
  observation.succeeded = GetNamedPipeInfo(
      pipe, &observation.flags, nullptr, nullptr, nullptr) != FALSE;
  observation.error = observation.succeeded ? ERROR_SUCCESS : GetLastError();
}

bool inspectPipeModeControl(const std::wstring &name, DWORD remoteMode,
                            SecurityContext &security,
                            PipeModeObservation &observation) {
  const DWORD openMode =
      PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
  const DWORD pipeMode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | remoteMode;
  UniqueHandle pipe(CreateNamedPipeW(
      name.c_str(), openMode, pipeMode, kMaximumPipeInstances,
      kPipeBufferBytes, kPipeBufferBytes, kConnectionTimeoutMs,
      &security.attributes));
  if (!pipe) return false;
  observePipeMode(pipe.get(), observation);
  return true;
}

int reportPipeModeControls() {
  SecurityContext security;
  if (!createSecurityContext(security)) return 1;
  const std::wstring prefix =
      L"\\\\.\\pipe\\gpt-repo-pipe-mode-" +
      std::to_wstring(GetCurrentProcessId()) + L"-" +
      std::to_wstring(GetTickCount64());
  PipeModeObservation acceptObservation;
  PipeModeObservation rejectObservation;
  PipeModeObservation productionFirstObservation;
  PipeModeObservation productionSuccessorObservation;
  if (!inspectPipeModeControl(prefix + L"-accept", PIPE_ACCEPT_REMOTE_CLIENTS,
                              security, acceptObservation) ||
      !inspectPipeModeControl(prefix + L"-reject", PIPE_REJECT_REMOTE_CLIENTS,
                              security, rejectObservation)) {
    const DWORD error = GetLastError();
    writeStdout("PIPE_MODE_CONTROL_CREATE_FAILED\t" + std::to_string(error) + "\n");
    return 2;
  }
  const std::wstring productionName = prefix + L"-production";
  DWORD productionFirstMode = 0;
  UniqueHandle productionFirst(createServerPipe(
      productionName, security, true, &productionFirstMode));
  if (!productionFirst) {
    const DWORD error = GetLastError();
    writeStdout("PRODUCTION_PIPE_CREATE_FAILED\tfirst\t" +
                std::to_string(error) + "\n");
    return 2;
  }
  observePipeMode(productionFirst.get(), productionFirstObservation);

  DWORD productionSuccessorMode = 0;
  UniqueHandle productionSuccessor(createServerPipe(
      productionName, security, false, &productionSuccessorMode));
  if (!productionSuccessor) {
    const DWORD error = GetLastError();
    writeStdout("PRODUCTION_PIPE_CREATE_FAILED\tsuccessor\t" +
                std::to_string(error) + "\n");
    return 2;
  }
  observePipeMode(productionSuccessor.get(), productionSuccessorObservation);

  const std::string output =
      std::string("accept\t") + (acceptObservation.succeeded ? "ok" : "error") +
      "\t" + std::to_string(acceptObservation.flags) +
      "\t" + std::to_string(acceptObservation.error) + "\n" +
      "reject\t" + (rejectObservation.succeeded ? "ok" : "error") +
      "\t" + std::to_string(rejectObservation.flags) +
      "\t" + std::to_string(rejectObservation.error) + "\n" +
      "production-first\t" + std::to_string(productionFirstMode) +
      "\t" + (productionFirstObservation.succeeded ? "ok" : "error") +
      "\t" + std::to_string(productionFirstObservation.flags) +
      "\t" + std::to_string(productionFirstObservation.error) + "\n" +
      "production-successor\t" + std::to_string(productionSuccessorMode) +
      "\t" + (productionSuccessorObservation.succeeded ? "ok" : "error") +
      "\t" + std::to_string(productionSuccessorObservation.flags) +
      "\t" + std::to_string(productionSuccessorObservation.error) + "\n";
  return writeStdout(output) ? 0 : 3;
}

int claimPipeInstance(const std::wstring &endpoint) {
  if (!validLocalPipeName(endpoint)) return 4;
  SecurityContext security;
  if (!createSecurityContext(security)) {
    writeStdout("SECURITY_FAILED\n");
    return 5;
  }
  HANDLE raw = createServerPipe(endpoint, security, false);
  if (raw == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    return writeStdout("NOT_CREATED\t" + std::to_string(error) + "\n") ? 0 : 6;
  }
  UniqueHandle pipe(raw);
  return writeStdout("CREATED\n") ? 0 : 6;
}
#endif

int discover() {
  SecurityContext security;
  if (!createSecurityContext(security)) return 40;
  std::wstring directory;
  bool exists = false;
  if (!getAdminDirectory(security, false, directory, exists)) return 41;
  std::vector<InstanceRecord> records;
  if (exists && !enumerateRecords(directory, security, records)) return 42;
  std::string output = "{\"records\":[";
  for (size_t index = 0; index < records.size(); ++index) {
    if (index > 0) output.push_back(',');
    output.append(recordJson(records[index]));
  }
  output.append("]}\n");
  return writeStdout(output) ? 0 : 43;
}

}  // namespace

int wmain(int argc, wchar_t *argv[]) {
  if (argc < 2) return 1;
#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  if (wcscmp(argv[1], L"pipe-info-controls") == 0 && argc == 2) {
    return reportPipeModeControls();
  }
  if (wcscmp(argv[1], L"claim") == 0 && argc == 3) return claimPipeInstance(argv[2]);
#endif
  if (wcscmp(argv[1], L"discover") == 0 && argc == 2) return discover();
  if (wcscmp(argv[1], L"serve") == 0 && argc == 4) {
    DWORD serverPid = 0;
    if (!parsePositivePid(argv[2], serverPid)) return 2;
    const std::string instanceId = narrowAscii(argv[3]);
    if (!isValidUuid(instanceId)) return 3;
    return serve(serverPid, instanceId);
  }
  if (wcscmp(argv[1], L"client") == 0 && argc == 6) {
    wchar_t *end = nullptr;
    const unsigned long timeout = wcstoul(argv[3], &end, 10);
    if (end == argv[3] || *end != L'\0' ||
        (timeout != kProbeTimeoutMs && timeout != kReloadAcknowledgmentTimeoutMs)) return 5;
    DWORD expectedHelperPid = 0;
    ULONGLONG expectedCreationTime = 0;
    if (!parsePositivePid(argv[4], expectedHelperPid) ||
        !parsePositiveUint64(argv[5], expectedCreationTime)) return 5;
    return client(argv[2], static_cast<DWORD>(timeout), expectedHelperPid,
                  expectedCreationTime);
  }
  return 4;
}
