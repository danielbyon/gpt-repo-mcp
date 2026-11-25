#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <iterator>
#include <string>
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
constexpr DWORD kIoTimeoutMs = 5'000;
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
  std::string instanceId;
  std::string endpoint;
};

enum class IoWaitResult { kCompleted, kParentExited, kTimedOut, kFailed };

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
  return writeHandle(GetStdHandle(STD_OUTPUT_HANDLE),
                     reinterpret_cast<const BYTE *>(value.data()),
                     static_cast<DWORD>(value.size()));
}

bool writeStdoutBytes(const BYTE *bytes, DWORD size) {
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
bool hasOwnerOnlyDacl(HANDLE handle, const SecurityContext &security) {
  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const DWORD error = GetSecurityInfo(handle, SE_FILE_OBJECT,
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
        valid = ace->Mask == GENERIC_ALL && EqualSid(aceSid, security.userSid) != FALSE;
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
         hasOwnerOnlyDacl(handle, security);
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
  output = raw;
  return verifyFileHandle(output, security, true);
}

bool createOrVerifyDirectory(const std::wstring &path, SecurityContext &security) {
  if (CreateDirectoryW(path.c_str(), &security.attributes) == FALSE) {
    const DWORD error = GetLastError();
    if (error != ERROR_ALREADY_EXISTS) return false;
  }
  HANDLE directory = nullptr;
  if (!openVerifiedDirectory(path, security, directory)) return false;
  CloseHandle(directory);
  return true;
}

// Locates the per-user discovery directory and optionally creates its secured path.
constexpr int kServeLocalAppDataRejected = 50;
constexpr int kServeAdminRootSetupFailed = 51;
constexpr int kServeAdminDirectorySetupFailed = 52;

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
    if (!createOrVerifyDirectory(root, security)) {
      if (createFailureCode != nullptr) *createFailureCode = kServeAdminRootSetupFailed;
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
  return "{\"protocol_version\":1,\"server_pid\":" +
         std::to_string(record.serverPid) + ",\"helper_pid\":" +
         std::to_string(record.helperPid) + ",\"instance_id\":\"" +
         record.instanceId + "\",\"endpoint\":\"" +
         jsonEscape(record.endpoint) + "\"}";
}

std::wstring recordFileName(const InstanceRecord &record) {
  return L"server-" + std::to_wstring(record.serverPid) + L"-" +
         widenAscii(record.instanceId) + L".record";
}

std::string recordContents(const InstanceRecord &record) {
  return "protocol_version=1\nserver_pid=" + std::to_string(record.serverPid) +
         "\nhelper_pid=" + std::to_string(record.helperPid) +
         "\ninstance_id=" + record.instanceId + "\nendpoint=" + record.endpoint + "\n";
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
  std::string instanceId;
  std::string endpoint;
  if (!readLine(serverPid) || serverPid.empty() ||
      contents.compare(cursor, 11, "helper_pid=") != 0) return false;
  cursor += 11;
  if (!readLine(helperPid) || helperPid.empty() ||
      contents.compare(cursor, 12, "instance_id=") != 0) return false;
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
      current.instanceId != expected.instanceId || current.endpoint != expected.endpoint) return true;
  return DeleteFileW(path.c_str()) != FALSE || GetLastError() == ERROR_FILE_NOT_FOUND;
}

bool readAllControlLine(HANDLE input, HANDLE parentProcess, std::string &line) {
  line.clear();
  const ULONGLONG deadline = GetTickCount64() + kIoTimeoutMs;
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

bool finishOverlapped(HANDLE pipe, OVERLAPPED &operation, HANDLE parentProcess,
                      DWORD &transferred) {
  const IoWaitResult wait = waitForIo(operation.hEvent, parentProcess, kIoTimeoutMs);
  if (wait != IoWaitResult::kCompleted) {
    CancelIoEx(pipe, &operation);
    WaitForSingleObject(operation.hEvent, INFINITE);
    SetLastError(wait == IoWaitResult::kParentExited ? ERROR_OPERATION_ABORTED
        : wait == IoWaitResult::kTimedOut ? ERROR_SEM_TIMEOUT : ERROR_GEN_FAILURE);
    return false;
  }
  return GetOverlappedResult(pipe, &operation, &transferred, FALSE) != FALSE;
}

bool readPipeMessage(HANDLE pipe, HANDLE parentProcess, std::vector<BYTE> &message) {
  BYTE buffer[kMaximumInputBytes + 1];
  DWORD read = 0;
  OVERLAPPED operation{};
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) return false;
  operation.hEvent = event.get();
  BOOL succeeded = ReadFile(pipe, buffer, sizeof(buffer), &read, &operation);
  if (!succeeded && GetLastError() == ERROR_IO_PENDING) {
    if (!finishOverlapped(pipe, operation, parentProcess, read)) return false;
    succeeded = TRUE;
  }
  if (!succeeded || read > kMaximumInputBytes) return false;
  message.assign(buffer, buffer + read);
  return hasValidFrame(message);
}

bool writePipeMessage(HANDLE pipe, const std::vector<BYTE> &message,
                      HANDLE parentProcess) {
  if (!hasValidFrame(message)) return false;
  DWORD written = 0;
  OVERLAPPED operation{};
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) return false;
  operation.hEvent = event.get();
  BOOL succeeded = WriteFile(pipe, message.data(), static_cast<DWORD>(message.size()),
                             &written, &operation);
  if (!succeeded && GetLastError() == ERROR_IO_PENDING) {
    if (!finishOverlapped(pipe, operation, parentProcess, written)) return false;
  } else if (!succeeded) {
    return false;
  }
  return written == message.size();
}

enum class ConnectResult { kConnected, kLateControl, kShutdown, kParentGone, kFailed };

ConnectResult connectPipe(HANDLE pipe, HANDLE parentProcess, HANDLE controlInput) {
  OVERLAPPED operation{};
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) return ConnectResult::kFailed;
  operation.hEvent = event.get();
  const BOOL connected = ConnectNamedPipe(pipe, &operation);
  if (connected) return ConnectResult::kConnected;
  const DWORD error = GetLastError();
  if (error == ERROR_PIPE_CONNECTED) return ConnectResult::kConnected;
  if (error != ERROR_IO_PENDING) return ConnectResult::kFailed;

  HANDLE handles[2] = {operation.hEvent, parentProcess};
  for (;;) {
    const DWORD result = WaitForMultipleObjects(2, handles, FALSE, 50);
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
    if (result != WAIT_TIMEOUT) {
      CancelIoEx(pipe, &operation);
      WaitForSingleObject(operation.hEvent, INFINITE);
      return ConnectResult::kFailed;
    }

    DWORD available = 0;
    if (!PeekNamedPipe(controlInput, nullptr, 0, nullptr, &available, nullptr)) {
      CancelIoEx(pipe, &operation);
      WaitForSingleObject(operation.hEvent, INFINITE);
      return ConnectResult::kParentGone;
    }
    if (available > 0) {
      std::string line;
      if (!readAllControlLine(controlInput, parentProcess, line)) {
        CancelIoEx(pipe, &operation);
        WaitForSingleObject(operation.hEvent, INFINITE);
        return ConnectResult::kParentGone;
      }
      if (line == "SHUTDOWN") {
        CancelIoEx(pipe, &operation);
        WaitForSingleObject(operation.hEvent, INFINITE);
        return ConnectResult::kShutdown;
      }
      // Late control output belongs to a client that already timed out.
      if (line == "ABORT" || line.rfind("RESPONSE\t", 0) == 0) {
        CancelIoEx(pipe, &operation);
        WaitForSingleObject(operation.hEvent, INFINITE);
        return ConnectResult::kLateControl;
      }
      CancelIoEx(pipe, &operation);
      WaitForSingleObject(operation.hEvent, INFINITE);
      SetLastError(ERROR_INVALID_DATA);
      return ConnectResult::kFailed;
    }
  }
}

// Creates one local-only pipe instance with the process user's protected ACL.
HANDLE createServerPipe(const std::wstring &name, SecurityContext &security,
                        bool firstInstance) {
  DWORD flags = FILE_FLAG_OVERLAPPED;
  if (firstInstance) flags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
  return CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | flags,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
      1, kPipeBufferBytes, kPipeBufferBytes, kIoTimeoutMs,
      &security.attributes);
}

enum class ControlResult { kResponse, kAbort, kShutdown, kParentGone };

ControlResult waitForControlResponse(HANDLE pipe, HANDLE parentProcess,
                                     std::vector<BYTE> &response) {
  const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  const ULONGLONG deadline = GetTickCount64() + kIoTimeoutMs;
  while (GetTickCount64() < deadline) {
    if (WaitForSingleObject(parentProcess, 0) == WAIT_OBJECT_0) return ControlResult::kParentGone;
    DWORD available = 0;
    if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) return ControlResult::kParentGone;
    if (available == 0) {
      Sleep(20);
      continue;
    }
    std::string line;
    if (!readAllControlLine(input, parentProcess, line)) return ControlResult::kParentGone;
    if (line == "SHUTDOWN") return ControlResult::kShutdown;
    if (line == "ABORT") return ControlResult::kAbort;
    constexpr char responsePrefix[] = "RESPONSE\t";
    if (line.rfind(responsePrefix, 0) != 0) return ControlResult::kAbort;
    if (!decodeBase64(line.substr(sizeof(responsePrefix) - 1), response) ||
        !hasValidFrame(response)) return ControlResult::kAbort;
    if (!writePipeMessage(pipe, response, parentProcess)) return ControlResult::kAbort;
    return ControlResult::kResponse;
  }
  return ControlResult::kAbort;
}

ControlResult handleServerConnection(HANDLE pipe, HANDLE parentProcess) {
  std::vector<BYTE> request;
  if (!readPipeMessage(pipe, parentProcess, request)) {
    return WaitForSingleObject(parentProcess, 0) == WAIT_OBJECT_0
        ? ControlResult::kParentGone : ControlResult::kAbort;
  }
  const std::string line = "REQUEST\t" + encodeBase64(request.data(), request.size()) + "\n";
  if (!writeStdout(line)) return ControlResult::kParentGone;
  std::vector<BYTE> response;
  return waitForControlResponse(pipe, parentProcess, response);
}

bool writeReady(const InstanceRecord &record) {
  const std::string line = "READY\t" + recordJson(record) + "\n";
  return writeStdout(line);
}

// Publishes this instance's local endpoint and relays requests until shutdown.
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
  record.instanceId = instanceId;
  record.endpoint = narrowAscii(name);
  std::wstring recordPath;
  if (record.endpoint.empty() || !publishRecord(directory, security, record, recordPath)) return 25;
  if (!writeReady(record)) {
    removeRecordIfSame(recordPath, security, record);
    return 26;
  }

  int exitCode = 0;
  for (;;) {
    if (WaitForSingleObject(parentProcess.get(), 0) == WAIT_OBJECT_0) break;
    const ConnectResult connection = connectPipe(pipe.get(), parentProcess.get(), GetStdHandle(STD_INPUT_HANDLE));
    if (connection == ConnectResult::kShutdown || connection == ConnectResult::kParentGone) break;
    if (connection == ConnectResult::kLateControl) {
      pipe.reset();
      pipe.reset(createServerPipe(name, security, false));
      if (!pipe) {
        exitCode = 29;
        break;
      }
      continue;
    }
    if (connection == ConnectResult::kConnected) {
      const ControlResult result = handleServerConnection(pipe.get(), parentProcess.get());
      DisconnectNamedPipe(pipe.get());
      if (result == ControlResult::kShutdown || result == ControlResult::kParentGone) break;
    } else {
      exitCode = 28;
      break;
    }
    pipe.reset();
    if (!pipe) {
      pipe.reset(createServerPipe(name, security, false));
      if (!pipe) {
        exitCode = 29;
        break;
      }
    }
  }
  pipe.reset();
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

bool openClientPipe(const std::wstring &endpoint, HANDLE &pipe) {
  const DWORD access = FILE_READ_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
  for (int attempt = 0; attempt < 2; ++attempt) {
    HANDLE raw = CreateFileW(endpoint.c_str(), access, 0, nullptr, OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED, nullptr);
    if (raw != INVALID_HANDLE_VALUE) {
      pipe = raw;
      DWORD mode = PIPE_READMODE_MESSAGE;
      if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) {
        CloseHandle(pipe);
        pipe = INVALID_HANDLE_VALUE;
        return false;
      }
      return true;
    }
    const DWORD error = GetLastError();
    if (error != ERROR_PIPE_BUSY || !WaitNamedPipeW(endpoint.c_str(), kIoTimeoutMs)) return false;
  }
  return false;
}

bool clientWrite(HANDLE pipe, const std::vector<BYTE> &request, DWORD &written) {
  OVERLAPPED operation{};
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!event) return false;
  operation.hEvent = event.get();
  BOOL succeeded = WriteFile(pipe, request.data(), static_cast<DWORD>(request.size()),
                             &written, &operation);
  if (!succeeded && GetLastError() == ERROR_IO_PENDING) {
    if (!finishOverlapped(pipe, operation, nullptr, written)) return false;
  } else if (!succeeded) {
    return false;
  }
  return written == request.size();
}

#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
const wchar_t *testFault() {
  static thread_local wchar_t value[64]{};
  const DWORD length = GetEnvironmentVariableW(L"GPT_REPO_ADMIN_TEST_FAULT", value,
                                                static_cast<DWORD>(std::size(value)));
  if (length == 0 || length >= std::size(value)) return L"";
  return value;
}
#endif

int client(const std::wstring &endpoint) {
  std::vector<BYTE> request;
  if (!validLocalPipeName(endpoint) ||
      !readAllInput(GetStdHandle(STD_INPUT_HANDLE), kMaximumInputBytes, request) ||
      !hasValidFrame(request)) {
    writeStdout("NOT_DISPATCHED\n");
    return 31;
  }

  HANDLE rawPipe = INVALID_HANDLE_VALUE;
  if (!openClientPipe(endpoint, rawPipe)) {
    writeStdout("NOT_DISPATCHED\n");
    return 34;
  }
  UniqueHandle pipe(rawPipe);

#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  if (wcscmp(testFault(), L"before-write") == 0) {
    writeStdout("NOT_DISPATCHED\n");
    return 32;
  }
  if (wcscmp(testFault(), L"silent-before-write") == 0) return 33;
#endif

  DWORD written = 0;
  const bool writeSucceeded = clientWrite(pipe.get(), request, written);
  if (!writeSucceeded) {
    writeStdout("INDETERMINATE\n");
    return 35;
  }

#ifdef GPT_REPO_CONFIGURATION_ADMIN_TESTING
  if (wcscmp(testFault(), L"after-write") == 0 ||
      wcscmp(testFault(), L"lose-dispatch-notification") == 0) return 36;
#endif

  std::vector<BYTE> response;
  if (!readPipeMessage(pipe.get(), nullptr, response)) {
    writeStdout("INDETERMINATE\n");
    return 37;
  }
  if (!writeStdout("RESPONSE\n") ||
      !writeStdoutBytes(response.data(), static_cast<DWORD>(response.size()))) return 38;
  return 0;
}

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
  if (wcscmp(argv[1], L"discover") == 0 && argc == 2) return discover();
  if (wcscmp(argv[1], L"serve") == 0 && argc == 4) {
    DWORD serverPid = 0;
    if (!parsePositivePid(argv[2], serverPid)) return 2;
    const std::string instanceId = narrowAscii(argv[3]);
    if (!isValidUuid(instanceId)) return 3;
    return serve(serverPid, instanceId);
  }
  if (wcscmp(argv[1], L"client") == 0 && argc == 3) return client(argv[2]);
  return 4;
}
