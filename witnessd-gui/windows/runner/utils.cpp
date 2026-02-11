#include "utils.h"

#include <flutter_windows.h>
#include <io.h>
#include <stdio.h>
#include <windows.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <propkey.h>
#include <propvarutil.h>

#include <iostream>

#include "resource.h"

void CreateAndAttachConsole() {
  if (::AllocConsole()) {
    FILE *unused;
    if (freopen_s(&unused, "CONOUT$", "w", stdout)) {
      _dup2(_fileno(stdout), 1);
    }
    if (freopen_s(&unused, "CONOUT$", "w", stderr)) {
      _dup2(_fileno(stdout), 2);
    }
    std::ios::sync_with_stdio();
    FlutterDesktopResyncOutputStreams();
  }
}

std::vector<std::string> GetCommandLineArguments() {
  // Convert the UTF-16 command line arguments to UTF-8 for the Engine to use.
  int argc;
  wchar_t** argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
  if (argv == nullptr) {
    return std::vector<std::string>();
  }

  std::vector<std::string> command_line_arguments;

  // Skip the first argument as it's the binary name.
  for (int i = 1; i < argc; i++) {
    command_line_arguments.push_back(Utf8FromUtf16(argv[i]));
  }

  ::LocalFree(argv);

  return command_line_arguments;
}

std::string Utf8FromUtf16(const wchar_t* utf16_string) {
  if (utf16_string == nullptr) {
    return std::string();
  }
  unsigned int target_length = ::WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, utf16_string,
      -1, nullptr, 0, nullptr, nullptr)
    -1; // remove the trailing null character
  int input_length = (int)wcslen(utf16_string);
  std::string utf8_string;
  if (target_length == 0 || target_length > utf8_string.max_size()) {
    return utf8_string;
  }
  utf8_string.resize(target_length);
  int converted_length = ::WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, utf16_string,
      input_length, utf8_string.data(), target_length, nullptr, nullptr);
  if (converted_length == 0) {
    return std::string();
  }
  return utf8_string;
}

namespace {

HRESULT CreateShellLink(const std::wstring& app_path,
                        const std::wstring& args,
                        const std::wstring& title,
                        IShellLinkW** out_link) {
  if (!out_link) {
    return E_INVALIDARG;
  }
  *out_link = nullptr;

  IShellLinkW* link = nullptr;
  HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&link));
  if (FAILED(hr)) {
    return hr;
  }

  link->SetPath(app_path.c_str());
  link->SetArguments(args.c_str());
  link->SetIconLocation(app_path.c_str(), 0);

  IPropertyStore* props = nullptr;
  hr = link->QueryInterface(IID_PPV_ARGS(&props));
  if (SUCCEEDED(hr)) {
    PROPVARIANT pv;
    hr = InitPropVariantFromString(title.c_str(), &pv);
    if (SUCCEEDED(hr)) {
      props->SetValue(PKEY_Title, pv);
      props->Commit();
      PropVariantClear(&pv);
    }
    props->Release();
  }

  *out_link = link;
  return S_OK;
}

}  // namespace

bool SetupJumpList(const std::wstring& app_id, const std::wstring& app_path) {
  ICustomDestinationList* dest_list = nullptr;
  HRESULT hr = CoCreateInstance(CLSID_DestinationList, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&dest_list));
  if (FAILED(hr)) {
    return false;
  }

  dest_list->SetAppID(app_id.c_str());

  UINT max_slots = 0;
  IObjectArray* removed = nullptr;
  hr = dest_list->BeginList(&max_slots, IID_PPV_ARGS(&removed));
  if (FAILED(hr)) {
    dest_list->Release();
    return false;
  }

  IObjectCollection* collection = nullptr;
  hr = CoCreateInstance(CLSID_EnumerableObjectCollection, nullptr, CLSCTX_INPROC_SERVER,
                        IID_PPV_ARGS(&collection));
  if (FAILED(hr)) {
    if (removed) removed->Release();
    dest_list->Release();
    return false;
  }

  IShellLinkW* reports = nullptr;
  if (SUCCEEDED(CreateShellLink(app_path, L"--route=reports", L"Open Reports", &reports))) {
    collection->AddObject(reports);
    reports->Release();
  }

  IShellLinkW* forensics = nullptr;
  if (SUCCEEDED(CreateShellLink(app_path, L"--route=forensics", L"Forensics", &forensics))) {
    collection->AddObject(forensics);
    forensics->Release();
  }

  IShellLinkW* preferences = nullptr;
  if (SUCCEEDED(CreateShellLink(app_path, L"--route=preferences", L"Preferences", &preferences))) {
    collection->AddObject(preferences);
    preferences->Release();
  }

  IObjectArray* tasks = nullptr;
  hr = collection->QueryInterface(IID_PPV_ARGS(&tasks));
  if (SUCCEEDED(hr)) {
    dest_list->AddUserTasks(tasks);
    tasks->Release();
  }

  dest_list->CommitList();

  collection->Release();
  if (removed) removed->Release();
  dest_list->Release();
  return true;
}

void ShowNotification(HWND owner, const std::wstring& title, const std::wstring& message) {
  NOTIFYICONDATA nid = {};
  nid.cbSize = sizeof(nid);
  nid.hWnd = owner;
  nid.uID = 1;
  nid.uFlags = NIF_INFO | NIF_ICON | NIF_TIP;
  nid.dwInfoFlags = NIIF_INFO;
  wcsncpy_s(nid.szInfoTitle, title.c_str(), _TRUNCATE);
  wcsncpy_s(nid.szInfo, message.c_str(), _TRUNCATE);
  wcsncpy_s(nid.szTip, L"Witnessd", _TRUNCATE);

  HICON icon = LoadIcon(GetModuleHandle(nullptr), MAKEINTRESOURCE(101));
  nid.hIcon = icon;

  Shell_NotifyIcon(NIM_ADD, &nid);
  Shell_NotifyIcon(NIM_MODIFY, &nid);

  if (icon) {
    DestroyIcon(icon);
  }
  Shell_NotifyIcon(NIM_DELETE, &nid);
}
