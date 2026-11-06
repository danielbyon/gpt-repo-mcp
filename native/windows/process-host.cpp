#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cwchar>
#include <iterator>
#include <mutex>
#include <process.h>
#include <string>
#include <utility>
#include <vector>

#if (defined(GPT_REPO_PROCESS_HOST_EXPECT_X64) +                               \
     defined(GPT_REPO_PROCESS_HOST_EXPECT_ARM64) +                             \
     defined(GPT_REPO_PROCESS_HOST_EXPECT_X86)) != 1
#error "Select exactly one expected process-host architecture."
#endif

#if defined(_MSC_VER)
#if defined(GPT_REPO_PROCESS_HOST_EXPECT_X64) && !defined(_M_X64)
#error                                                                         \
    "The process-host output is labeled x64 but MSVC is targeting another architecture."
#endif
#if defined(GPT_REPO_PROCESS_HOST_EXPECT_X64) && defined(_M_ARM64EC)
#error "The process-host output is labeled x64 but MSVC is targeting ARM64EC."
#endif
#if defined(GPT_REPO_PROCESS_HOST_EXPECT_ARM64) &&                             \
    (!defined(_M_ARM64) || defined(_M_ARM64EC))
#error                                                                         \
    "The process-host output is labeled arm64 but MSVC is targeting another architecture."
#endif
#if defined(GPT_REPO_PROCESS_HOST_EXPECT_X86) && !defined(_M_IX86)
#error                                                                         \
    "The process-host output is labeled x86 but MSVC is targeting another architecture."
#endif
#else
#if defined(GPT_REPO_PROCESS_HOST_EXPECT_X64) &&                               \
    !(defined(__x86_64__) || defined(__amd64__))
#error                                                                         \
    "The process-host output is labeled x64 but the compiler is targeting another architecture."
#endif
#if defined(GPT_REPO_PROCESS_HOST_EXPECT_ARM64) && !defined(__aarch64__)
#error                                                                         \
    "The process-host output is labeled arm64 but the compiler is targeting another architecture."
#endif
#if defined(GPT_REPO_PROCESS_HOST_EXPECT_X86) && !defined(__i386__)
#error                                                                         \
    "The process-host output is labeled x86 but the compiler is targeting another architecture."
#endif
#endif

#ifndef PROC_THREAD_ATTRIBUTE_JOB_LIST
#define PROC_THREAD_ATTRIBUTE_JOB_LIST                                         \
  ProcThreadAttributeValue(13, FALSE, TRUE, FALSE)
#endif

namespace {

constexpr BYTE kStdoutFrame = 1;
constexpr BYTE kStderrFrame = 2;
constexpr BYTE kResultFrame = 3;
constexpr DWORD kOutputChunkBytes = 32 * 1024;
constexpr DWORD kPollIntervalMs = 10;
constexpr DWORD kCleanupDeadlineMs = 650;
constexpr DWORD kMaximumCommandLineChars = 32 * 1024 - 1;

enum class ResultStatus : BYTE {
  Completed = 0,
  LaunchFailed = 1,
  CleanupUnconfirmed = 2,
  CancelledBeforeStart = 3,
  CancelledConfirmed = 4,
  SupervisionFailed = 5
};

class UniqueHandle {
public:
  explicit UniqueHandle(HANDLE handle = nullptr) : handle_(handle) {}
  ~UniqueHandle() { reset(); }

  UniqueHandle(const UniqueHandle &) = delete;
  UniqueHandle &operator=(const UniqueHandle &) = delete;

  UniqueHandle(UniqueHandle &&other) noexcept
      : handle_(std::exchange(other.handle_, nullptr)) {}
  UniqueHandle &operator=(UniqueHandle &&other) noexcept {
    if (this != &other)
      reset(std::exchange(other.handle_, nullptr));
    return *this;
  }

  HANDLE get() const { return handle_; }
  explicit operator bool() const {
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
  }

  void reset(HANDLE handle = nullptr) {
    if (*this)
      CloseHandle(handle_);
    handle_ = handle;
  }

private:
  HANDLE handle_;
};

struct ControlState {
  bool start_seen = false;
  bool cancel_seen = false;
  bool eof = false;
  bool malformed = false;
  DWORD error = ERROR_SUCCESS;
};

struct PipeReaderState {
  std::atomic<bool> done{false};
  std::atomic<bool> failed{false};
  std::atomic<DWORD> error{ERROR_SUCCESS};
};

struct PipeReaderContext {
  HANDLE pipe;
  HANDLE output;
  BYTE frame_type;
  std::mutex *output_mutex;
  PipeReaderState *state;
};

struct ReconcileResult {
  bool confirmed = false;
  DWORD error = ERROR_TIMEOUT;
};

#ifdef GPT_REPO_PROCESS_HOST_TESTING
// Test builds can inject failures in process resume and Job Object operations.
bool testFault(const wchar_t *name) {
  wchar_t value[64]{};
  const DWORD length =
      GetEnvironmentVariableW(L"GPT_REPO_PROCESS_HOST_TEST_FAULT", value,
                              static_cast<DWORD>(std::size(value)));
  return length > 0 && length < std::size(value) &&
         std::wcscmp(value, name) == 0;
}
#else
bool testFault(const wchar_t *) { return false; }
#endif

bool writeAll(HANDLE handle, const BYTE *bytes, DWORD length) {
  DWORD offset = 0;
  while (offset < length) {
    DWORD written = 0;
    if (!WriteFile(handle, bytes + offset, length - offset, &written,
                   nullptr) ||
        written == 0)
      return false;
    offset += written;
  }
  return true;
}

bool writeFrame(HANDLE output, std::mutex &outputMutex, BYTE type,
                const BYTE *payload, DWORD length) {
  BYTE header[5]{};
  header[0] = type;
  header[1] = static_cast<BYTE>(length & 0xff);
  header[2] = static_cast<BYTE>((length >> 8) & 0xff);
  header[3] = static_cast<BYTE>((length >> 16) & 0xff);
  header[4] = static_cast<BYTE>((length >> 24) & 0xff);

  std::lock_guard<std::mutex> lock(outputMutex);
  return writeAll(output, header, static_cast<DWORD>(sizeof(header))) &&
         (length == 0 || writeAll(output, payload, length));
}

bool writeResult(HANDLE output, ResultStatus status, DWORD exitCode,
                 DWORD errorCode) {
  BYTE payload[9]{};
  payload[0] = static_cast<BYTE>(status);
  for (unsigned int index = 0; index < 4; ++index) {
    payload[1 + index] = static_cast<BYTE>((exitCode >> (index * 8)) & 0xff);
    payload[5 + index] = static_cast<BYTE>((errorCode >> (index * 8)) & 0xff);
  }
  std::mutex outputMutex;
  return writeFrame(output, outputMutex, kResultFrame, payload,
                    static_cast<DWORD>(sizeof(payload)));
}

unsigned int __stdcall readOutputPipe(void *parameter) {
  auto &context = *static_cast<PipeReaderContext *>(parameter);
  PipeReaderState &state = *context.state;
  BYTE buffer[kOutputChunkBytes];
  for (;;) {
    DWORD bytesRead = 0;
    if (!ReadFile(context.pipe, buffer, static_cast<DWORD>(sizeof(buffer)),
                  &bytesRead, nullptr)) {
      const DWORD error = GetLastError();
      if (error != ERROR_BROKEN_PIPE && error != ERROR_OPERATION_ABORTED) {
        state.error.store(error, std::memory_order_relaxed);
        state.failed.store(true, std::memory_order_release);
      }
      break;
    }
    if (bytesRead == 0)
      break;
    if (!writeFrame(context.output, *context.output_mutex, context.frame_type,
                    buffer, bytesRead)) {
      state.error.store(GetLastError(), std::memory_order_relaxed);
      state.failed.store(true, std::memory_order_release);
      break;
    }
  }
  state.done.store(true, std::memory_order_release);
  return 0;
}

UniqueHandle startPipeReader(PipeReaderContext &context) {
  const uintptr_t thread =
      _beginthreadex(nullptr, 0, readOutputPipe, &context, 0, nullptr);
  return UniqueHandle(reinterpret_cast<HANDLE>(thread));
}

bool stopPipeReader(HANDLE thread) {
  if (thread == nullptr || thread == INVALID_HANDLE_VALUE)
    return true;
  CancelSynchronousIo(thread);
  return WaitForSingleObject(thread, 100) == WAIT_OBJECT_0;
}

void stopHelperWithoutProtocol() {
  TerminateProcess(GetCurrentProcess(), 1);
  ExitProcess(1);
}

void acceptControlByte(ControlState &state, BYTE value, bool launchCommitted) {
  if (value == static_cast<BYTE>('C')) {
    state.cancel_seen = true;
    return;
  }
  if (value == static_cast<BYTE>('S') && !launchCommitted &&
      !state.start_seen) {
    state.start_seen = true;
    return;
  }
  state.malformed = true;
}

void pollControl(HANDLE input, ControlState &state, bool launchCommitted) {
  if (state.eof || state.error != ERROR_SUCCESS || state.malformed)
    return;

  for (;;) {
    DWORD available = 0;
    if (!PeekNamedPipe(input, nullptr, 0, nullptr, &available, nullptr)) {
      const DWORD error = GetLastError();
      if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA)
        state.eof = true;
      else
        state.error = error;
      return;
    }
    if (available == 0)
      return;
    if (available > 64) {
      state.malformed = true;
      return;
    }

    BYTE commands[64]{};
    DWORD bytesRead = 0;
    if (!ReadFile(
            input, commands,
            std::min<DWORD>(available, static_cast<DWORD>(sizeof(commands))),
            &bytesRead, nullptr)) {
      const DWORD error = GetLastError();
      if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA)
        state.eof = true;
      else
        state.error = error;
      return;
    }
    if (bytesRead == 0) {
      state.eof = true;
      return;
    }
    for (DWORD index = 0; index < bytesRead; ++index) {
      acceptControlByte(state, commands[index], launchCommitted);
      if (state.malformed)
        return;
    }
  }
}

bool queryActiveProcesses(HANDLE job, DWORD &activeProcesses) {
  if (testFault(L"job-query")) {
    SetLastError(ERROR_ACCESS_DENIED);
    return false;
  }
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
  if (!QueryInformationJobObject(
          job, JobObjectBasicAccountingInformation, &accounting,
          static_cast<DWORD>(sizeof(accounting)), nullptr)) {
    return false;
  }
  activeProcesses = accounting.ActiveProcesses;
  return true;
}

bool terminateJob(HANDLE job, DWORD exitCode) {
  if (testFault(L"job-terminate")) {
    SetLastError(ERROR_ACCESS_DENIED);
    return false;
  }
  return TerminateJobObject(job, exitCode) != FALSE;
}

bool pipeReadersHealthy(const PipeReaderState &stdoutState,
                        const PipeReaderState &stderrState) {
  return !stdoutState.failed.load(std::memory_order_acquire) &&
         !stderrState.failed.load(std::memory_order_acquire);
}

bool pipeReadersDone(const PipeReaderState &stdoutState,
                     const PipeReaderState &stderrState) {
  return stdoutState.done.load(std::memory_order_acquire) &&
         stderrState.done.load(std::memory_order_acquire);
}

ReconcileResult terminateAndReconcile(HANDLE job, HANDLE process,
                                      const PipeReaderState &stdoutState,
                                      const PipeReaderState &stderrState) {
  ReconcileResult result{};
  const bool terminateSucceeded = terminateJob(job, ERROR_CANCELLED);
  DWORD terminateError = terminateSucceeded ? ERROR_SUCCESS : GetLastError();
  const ULONGLONG deadline = GetTickCount64() + kCleanupDeadlineMs;
  bool querySucceeded = false;
  bool processExited = false;
  bool streamsDrained = false;

  do {
    DWORD activeProcesses = 0;
    querySucceeded = queryActiveProcesses(job, activeProcesses);
    if (!querySucceeded)
      result.error = GetLastError();

    const DWORD processWait = WaitForSingleObject(process, 0);
    processExited = processWait == WAIT_OBJECT_0;
    if (processWait == WAIT_FAILED)
      result.error = GetLastError();

    streamsDrained = pipeReadersDone(stdoutState, stderrState) &&
                     pipeReadersHealthy(stdoutState, stderrState);
    if (terminateSucceeded && querySucceeded && activeProcesses == 0 &&
        processExited && streamsDrained) {
      result.confirmed = true;
      result.error = ERROR_SUCCESS;
      return result;
    }
    if (GetTickCount64() >= deadline)
      break;
    Sleep(kPollIntervalMs);
  } while (true);

  if (!terminateSucceeded)
    result.error = terminateError;
  else if (result.error == ERROR_SUCCESS)
    result.error = ERROR_TIMEOUT;
  return result;
}

std::wstring quoteWindowsArgument(const wchar_t *argument) {
  std::wstring quoted;
  quoted.push_back(L'"');
  size_t backslashes = 0;
  for (const wchar_t *cursor = argument; *cursor != L'\0'; ++cursor) {
    if (*cursor == L'\\') {
      ++backslashes;
      continue;
    }
    if (*cursor == L'"') {
      quoted.append(backslashes * 2 + 1, L'\\');
      quoted.push_back(L'"');
      backslashes = 0;
      continue;
    }
    quoted.append(backslashes, L'\\');
    backslashes = 0;
    quoted.push_back(*cursor);
  }
  quoted.append(backslashes * 2, L'\\');
  quoted.push_back(L'"');
  return quoted;
}

std::wstring makeCommandLine(const wchar_t *executable, int argc,
                             wchar_t *argv[], int firstArgument,
                             bool verbatim) {
  std::wstring commandLine = quoteWindowsArgument(executable);
  if (verbatim) {
    for (int index = firstArgument; index < argc; ++index) {
      commandLine.push_back(L' ');
      commandLine.append(argv[index]);
    }
    return commandLine;
  }
  for (int index = firstArgument; index < argc; ++index) {
    commandLine.push_back(L' ');
    commandLine.append(quoteWindowsArgument(argv[index]));
  }
  return commandLine;
}

class AttributeList {
public:
  AttributeList() {
    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 2, 0, &bytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0)
      return;
    storage_.resize(bytes);
    list_ = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
    if (!InitializeProcThreadAttributeList(list_, 2, 0, &bytes))
      list_ = nullptr;
  }

  ~AttributeList() {
    if (list_ != nullptr)
      DeleteProcThreadAttributeList(list_);
  }

  AttributeList(const AttributeList &) = delete;
  AttributeList &operator=(const AttributeList &) = delete;

  bool valid() const { return list_ != nullptr; }
  LPPROC_THREAD_ATTRIBUTE_LIST get() const { return list_; }

private:
  std::vector<BYTE> storage_;
  LPPROC_THREAD_ATTRIBUTE_LIST list_ = nullptr;
};

bool makeChildPipe(UniqueHandle &parentRead, UniqueHandle &childWrite) {
  SECURITY_ATTRIBUTES security{};
  security.nLength = static_cast<DWORD>(sizeof(security));
  security.bInheritHandle = TRUE;
  HANDLE readHandle = nullptr;
  HANDLE writeHandle = nullptr;
  if (!CreatePipe(&readHandle, &writeHandle, &security, 0))
    return false;
  parentRead.reset(readHandle);
  childWrite.reset(writeHandle);
  if (!SetHandleInformation(parentRead.get(), HANDLE_FLAG_INHERIT, 0))
    return false;
  return true;
}

DWORD createCommandProcess(const wchar_t *executable, int argc, wchar_t *argv[],
                           int firstArgument, bool verbatim, HANDLE job,
                           PROCESS_INFORMATION &processInfo,
                           UniqueHandle &stdoutRead, UniqueHandle &stderrRead,
                           UniqueHandle &stdoutWrite,
                           UniqueHandle &stderrWrite) {
  UniqueHandle stdinHandle(
      CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!stdinHandle)
    return GetLastError();
  if (!SetHandleInformation(stdinHandle.get(), HANDLE_FLAG_INHERIT,
                            HANDLE_FLAG_INHERIT))
    return GetLastError();
  if (!makeChildPipe(stdoutRead, stdoutWrite) ||
      !makeChildPipe(stderrRead, stderrWrite))
    return GetLastError();

  // Restrict inheritance to child stdio; the Job and control handles stay
  // private.
  const HANDLE inheritedHandles[] = {stdinHandle.get(), stdoutWrite.get(),
                                     stderrWrite.get()};
  AttributeList attributes;
  if (!attributes.valid())
    return GetLastError() == ERROR_SUCCESS ? ERROR_NOT_ENOUGH_MEMORY
                                           : GetLastError();
  HANDLE jobForChild = job;
  if (!UpdateProcThreadAttribute(attributes.get(), 0,
                                 PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobForChild,
                                 sizeof(jobForChild), nullptr, nullptr))
    return GetLastError();
  if (!UpdateProcThreadAttribute(attributes.get(), 0,
                                 PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 const_cast<HANDLE *>(inheritedHandles),
                                 sizeof(inheritedHandles), nullptr, nullptr))
    return GetLastError();

  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = static_cast<DWORD>(sizeof(startup));
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = stdinHandle.get();
  startup.StartupInfo.hStdOutput = stdoutWrite.get();
  startup.StartupInfo.hStdError = stderrWrite.get();
  startup.lpAttributeList = attributes.get();

  std::wstring commandLine =
      makeCommandLine(executable, argc, argv, firstArgument, verbatim);
  if (commandLine.empty() || commandLine.size() >= kMaximumCommandLineChars)
    return ERROR_FILENAME_EXCED_RANGE;
  std::vector<wchar_t> mutableCommandLine(commandLine.begin(),
                                          commandLine.end());
  mutableCommandLine.push_back(L'\0');

  // The Job-list attribute assigns the suspended child before its first
  // instruction runs.
  if (!CreateProcessW(
          executable, mutableCommandLine.data(), nullptr, nullptr, TRUE,
          EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
          nullptr, nullptr, &startup.StartupInfo, &processInfo)) {
    return GetLastError();
  }
  return ERROR_SUCCESS;
}

bool createJob(UniqueHandle &job) {
  if (testFault(L"job-init")) {
    SetLastError(ERROR_ACCESS_DENIED);
    return false;
  }
  job.reset(CreateJobObjectW(nullptr, nullptr));
  if (!job)
    return false;
  if (!SetHandleInformation(job.get(), HANDLE_FLAG_INHERIT, 0))
    return false;

  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  return SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                                 &limits,
                                 static_cast<DWORD>(sizeof(limits))) != FALSE;
}

int runHost(int argc, wchar_t *argv[]) {
  const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
  if (input == nullptr || input == INVALID_HANDLE_VALUE || output == nullptr ||
      output == INVALID_HANDLE_VALUE) {
    return 1;
  }

  if (argc < 3 || std::wcscmp(argv[1], L"--") != 0) {
    writeResult(output, ResultStatus::LaunchFailed, 0, ERROR_INVALID_PARAMETER);
    return 1;
  }
  const bool verbatim = std::wcscmp(argv[2], L"--verbatim") == 0;
  const int executableIndex = verbatim ? 3 : 2;
  if (argc <= executableIndex || argv[executableIndex][0] == L'\0') {
    writeResult(output, ResultStatus::LaunchFailed, 0, ERROR_INVALID_PARAMETER);
    return 1;
  }

  ControlState control;
  for (;;) {
    pollControl(input, control, false);
    if (control.malformed) {
      writeResult(output, ResultStatus::LaunchFailed, 0, ERROR_INVALID_DATA);
      return 1;
    }
    if (control.error != ERROR_SUCCESS) {
      writeResult(output, ResultStatus::LaunchFailed, 0, control.error);
      return 1;
    }
    if (control.cancel_seen || control.eof) {
      writeResult(output, ResultStatus::CancelledBeforeStart, 0, ERROR_SUCCESS);
      return 0;
    }
    if (control.start_seen)
      break;
    Sleep(kPollIntervalMs);
  }

  UniqueHandle job;
  if (!createJob(job)) {
    const DWORD error = GetLastError();
    writeResult(output, ResultStatus::LaunchFailed, 0, error);
    return 1;
  }

  UniqueHandle stdoutRead;
  UniqueHandle stderrRead;
  UniqueHandle stdoutWrite;
  UniqueHandle stderrWrite;
  PROCESS_INFORMATION processInfo{};
  const DWORD launchError = createCommandProcess(
      argv[executableIndex], argc, argv, executableIndex + 1, verbatim,
      job.get(), processInfo, stdoutRead, stderrRead, stdoutWrite, stderrWrite);
  if (launchError != ERROR_SUCCESS) {
    pollControl(input, control, true);
    const ResultStatus status = (control.cancel_seen || control.eof)
                                    ? ResultStatus::CancelledBeforeStart
                                    : ResultStatus::LaunchFailed;
    writeResult(output, status, 0,
                status == ResultStatus::LaunchFailed ? launchError
                                                     : ERROR_SUCCESS);
    return status == ResultStatus::LaunchFailed ? 1 : 0;
  }

  UniqueHandle process(processInfo.hProcess);
  UniqueHandle primaryThread(processInfo.hThread);
  stdoutWrite.reset();
  stderrWrite.reset();

  PipeReaderState stdoutState;
  PipeReaderState stderrState;
  std::mutex outputMutex;
  PipeReaderContext stdoutContext{stdoutRead.get(), output, kStdoutFrame,
                                  &outputMutex, &stdoutState};
  PipeReaderContext stderrContext{stderrRead.get(), output, kStderrFrame,
                                  &outputMutex, &stderrState};
  UniqueHandle stdoutReader = startPipeReader(stdoutContext);
  UniqueHandle stderrReader = startPipeReader(stderrContext);
  if (!stdoutReader || !stderrReader) {
    const ReconcileResult cleanup = terminateAndReconcile(
        job.get(), process.get(), stdoutState, stderrState);
    if (!stopPipeReader(stdoutReader.get()) ||
        !stopPipeReader(stderrReader.get()))
      stopHelperWithoutProtocol();
    const DWORD error =
        cleanup.confirmed ? ERROR_NOT_ENOUGH_MEMORY : cleanup.error;
    writeResult(output, ResultStatus::CleanupUnconfirmed, 0, error);
    return 1;
  }

  pollControl(input, control, true);
  if (control.cancel_seen || control.eof) {
    const ReconcileResult cleanup = terminateAndReconcile(
        job.get(), process.get(), stdoutState, stderrState);
    if (!cleanup.confirmed) {
      if (!stopPipeReader(stdoutReader.get()) ||
          !stopPipeReader(stderrReader.get()))
        stopHelperWithoutProtocol();
      writeResult(output, ResultStatus::CleanupUnconfirmed, 0, cleanup.error);
      return 1;
    }
    WaitForSingleObject(stdoutReader.get(), INFINITE);
    WaitForSingleObject(stderrReader.get(), INFINITE);
    writeResult(output, ResultStatus::CancelledBeforeStart, 0, ERROR_SUCCESS);
    return 0;
  }

  bool fatal = control.malformed || control.error != ERROR_SUCCESS;
  DWORD fatalError = control.malformed ? ERROR_INVALID_DATA : control.error;
  if (!fatal) {
    if (testFault(L"resume")) {
      fatal = true;
      fatalError = ERROR_ACCESS_DENIED;
    } else {
      const DWORD resumeCount = ResumeThread(primaryThread.get());
      if (resumeCount == static_cast<DWORD>(-1)) {
        fatal = true;
        fatalError = GetLastError();
      } else if (resumeCount != 1) {
        fatal = true;
        fatalError = ERROR_INVALID_STATE;
      }
    }
  }
  primaryThread.reset();
  if (fatal) {
    const ReconcileResult cleanup = terminateAndReconcile(
        job.get(), process.get(), stdoutState, stderrState);
    if (!cleanup.confirmed) {
      if (!stopPipeReader(stdoutReader.get()) ||
          !stopPipeReader(stderrReader.get()))
        stopHelperWithoutProtocol();
      writeResult(output, ResultStatus::CleanupUnconfirmed, 0, fatalError);
      return 1;
    }
    WaitForSingleObject(stdoutReader.get(), INFINITE);
    WaitForSingleObject(stderrReader.get(), INFINITE);
    writeResult(output, ResultStatus::SupervisionFailed, 0, fatalError);
    return 1;
  }

  bool processExited = false;
  DWORD exitCode = 0;

  for (;;) {
    pollControl(input, control, true);
    if (control.malformed || control.error != ERROR_SUCCESS) {
      fatal = true;
      fatalError = control.malformed ? ERROR_INVALID_DATA : control.error;
      break;
    }
    if (control.cancel_seen || control.eof)
      break;

    DWORD activeProcesses = 0;
    if (!queryActiveProcesses(job.get(), activeProcesses)) {
      fatal = true;
      fatalError = GetLastError();
      break;
    }
    if (!pipeReadersHealthy(stdoutState, stderrState)) {
      fatal = true;
      fatalError = stdoutState.failed.load(std::memory_order_acquire)
                       ? stdoutState.error.load(std::memory_order_relaxed)
                       : stderrState.error.load(std::memory_order_relaxed);
      if (fatalError == ERROR_SUCCESS)
        fatalError = ERROR_WRITE_FAULT;
      break;
    }

    const DWORD wait = WaitForSingleObject(process.get(), 0);
    if (wait == WAIT_FAILED) {
      fatal = true;
      fatalError = GetLastError();
      break;
    }
    processExited = wait == WAIT_OBJECT_0;
    if (processExited &&
        GetExitCodeProcess(process.get(), &exitCode) == FALSE) {
      fatal = true;
      fatalError = GetLastError();
      break;
    }

    if (processExited && activeProcesses == 0 &&
        pipeReadersDone(stdoutState, stderrState)) {
      pollControl(input, control, true);
      if (control.malformed || control.error != ERROR_SUCCESS) {
        fatal = true;
        fatalError = control.malformed ? ERROR_INVALID_DATA : control.error;
        break;
      }
      if (control.cancel_seen || control.eof)
        break;

      WaitForSingleObject(stdoutReader.get(), INFINITE);
      WaitForSingleObject(stderrReader.get(), INFINITE);
      if (pipeReadersHealthy(stdoutState, stderrState)) {
        writeResult(output, ResultStatus::Completed, exitCode, ERROR_SUCCESS);
        return 0;
      }
      fatal = true;
      fatalError = ERROR_WRITE_FAULT;
      break;
    }
    Sleep(kPollIntervalMs);
  }

  const ReconcileResult cleanup =
      terminateAndReconcile(job.get(), process.get(), stdoutState, stderrState);
  if (!cleanup.confirmed) {
    if (!stopPipeReader(stdoutReader.get()) ||
        !stopPipeReader(stderrReader.get()))
      stopHelperWithoutProtocol();
    writeResult(output, ResultStatus::CleanupUnconfirmed, 0,
                fatal && fatalError != ERROR_SUCCESS ? fatalError
                                                     : cleanup.error);
    return 1;
  }

  WaitForSingleObject(stdoutReader.get(), INFINITE);
  WaitForSingleObject(stderrReader.get(), INFINITE);
  if (fatal) {
    writeResult(output, ResultStatus::SupervisionFailed, 0,
                fatalError == ERROR_SUCCESS ? cleanup.error : fatalError);
    return 1;
  }
  writeResult(output, ResultStatus::CancelledConfirmed, ERROR_CANCELLED,
              ERROR_SUCCESS);
  return 0;
}

} // namespace

int wmain(int argc, wchar_t *argv[]) { return runHost(argc, argv); }
