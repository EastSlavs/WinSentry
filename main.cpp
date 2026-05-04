#include <windows.h>
#include <iphlpapi.h>
#include <iomanip>
#include <cstdint>
#include <sstream>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_TOGGLE 1001
#define ID_TRAY_EXIT 1002
#define ID_TRAY_TIMER 1003

// ==========================================
// 全局状态与数据结构
// ==========================================
struct HardwareData {
    double cpuUsage = 0.0;
    DWORD memLoad = 0;
    double usedMemGB = 0.0, totalMemGB = 0.0;
    unsigned int gpuTemp = 0, gpuUtil = 0, vramUtil = 0;
    std::string dlSpeed = "0.00 KB/s", ulSpeed = "0.00 KB/s";
} g_hwData;

FILETIME g_prevIdleTime, g_prevKernelTime, g_prevUserTime;
uint64_t g_prevNetIn = 0, g_prevNetOut = 0;
void* g_gpuHandle = nullptr;
bool g_hasGPU = false;
bool g_showOverlay = true;

bool g_isTiming = false;
std::chrono::steady_clock::time_point g_startTime;

int g_alertCount = 0;
int g_cooldown = 0;

NOTIFYICONDATAA g_nid = {0};

typedef struct { unsigned int gpu; unsigned int memory; } nvmlUtilization_t;
typedef int (*nvmlInit_t)(void);
typedef int (*nvmlDeviceGetHandleByIndex_t)(unsigned int index, void** device);
typedef int (*nvmlDeviceGetTemperature_t)(void* device, int sensorType, unsigned int* temp);
typedef int (*nvmlDeviceGetUtilizationRates_t)(void* device, nvmlUtilization_t* utilization);
nvmlDeviceGetTemperature_t nvmlGetTemp = nullptr;
nvmlDeviceGetUtilizationRates_t nvmlGetUtil = nullptr;

// ==========================================
// 数据采集与审计逻辑
// ==========================================
std::string FormatSpeed(uint64_t bytes) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    if (bytes >= 1024 * 1024) oss << (bytes / 1048576.0) << " MB/s";
    else oss << (bytes / 1024.0) << " KB/s";
    return oss.str();
}

uint64_t FT2U64(const FILETIME& ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime; uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart;
}

void InitHardware() {
    HMODULE nvml = LoadLibraryA("nvml.dll");
    if (nvml) {
        auto init = (nvmlInit_t)GetProcAddress(nvml, "nvmlInit_v2");
        auto getHandle = (nvmlDeviceGetHandleByIndex_t)GetProcAddress(nvml, "nvmlDeviceGetHandleByIndex_v2");
        nvmlGetTemp = (nvmlDeviceGetTemperature_t)GetProcAddress(nvml, "nvmlDeviceGetTemperature");
        nvmlGetUtil = (nvmlDeviceGetUtilizationRates_t)GetProcAddress(nvml, "nvmlDeviceGetUtilizationRates");
        if (init && getHandle && nvmlGetTemp && nvmlGetUtil && init() == 0 && getHandle(0, &g_gpuHandle) == 0) {
            g_hasGPU = true;
        }
    }
    GetSystemTimes(&g_prevIdleTime, &g_prevKernelTime, &g_prevUserTime);
}

void LogAnomaly() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char timeStr[64];
    sprintf_s(timeStr, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::ofstream file("WinSentry_Audit.csv", std::ios::app);
    if (file.is_open()) {
        file.seekp(0, std::ios::end);
        if (file.tellp() == 0) file << "Time,CPU(%),MemUsed(GB),GPUTemp(C),GPUUtil(%),Down,Up\n";
        file << timeStr << "," << std::fixed << std::setprecision(1) << g_hwData.cpuUsage << ","
             << g_hwData.usedMemGB << "," << g_hwData.gpuTemp << "," << g_hwData.gpuUtil << ","
             << g_hwData.dlSpeed << "," << g_hwData.ulSpeed << "\n";
    }
}

void CheckAuditRules() {
    if (g_cooldown > 0) { g_cooldown--; return; }
    if (g_hwData.cpuUsage > 85.0 || g_hwData.gpuTemp > 80) {
        if (++g_alertCount >= 5) {
            LogAnomaly();
            g_alertCount = 0;
            g_cooldown = 60;
        }
    } else {
        g_alertCount = 0;
    }
}

void UpdateHardwareData() {
    MEMORYSTATUSEX mem = { sizeof(MEMORYSTATUSEX) };
    GlobalMemoryStatusEx(&mem);
    g_hwData.memLoad = mem.dwMemoryLoad;
    g_hwData.totalMemGB = mem.ullTotalPhys / 1073741824.0;
    g_hwData.usedMemGB = (mem.ullTotalPhys - mem.ullAvailPhys) / 1073741824.0;

    FILETIME idle, kernel, user;
    GetSystemTimes(&idle, &kernel, &user);
    uint64_t sysDelta = (FT2U64(kernel) - FT2U64(g_prevKernelTime)) + (FT2U64(user) - FT2U64(g_prevUserTime));
    uint64_t idleDelta = FT2U64(idle) - FT2U64(g_prevIdleTime);
    if (sysDelta > 0) g_hwData.cpuUsage = (sysDelta - idleDelta) * 100.0 / sysDelta;
    g_prevIdleTime = idle; g_prevKernelTime = kernel; g_prevUserTime = user;

    if (g_hasGPU) {
        nvmlUtilization_t util = {0, 0};
        nvmlGetTemp(g_gpuHandle, 0, &g_hwData.gpuTemp);
        nvmlGetUtil(g_gpuHandle, &util);
        g_hwData.gpuUtil = util.gpu;
        g_hwData.vramUtil = util.memory;
    }

    uint64_t inBytes = 0, outBytes = 0;
    DWORD dwSize = 0;
    if (GetIfTable(NULL, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buf(dwSize);
        MIB_IFTABLE* table = reinterpret_cast<MIB_IFTABLE*>(buf.data());
        if (GetIfTable(table, &dwSize, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < table->dwNumEntries; i++) {
                if (table->table[i].dwType != MIB_IF_TYPE_LOOPBACK) {
                    inBytes += table->table[i].dwInOctets;
                    outBytes += table->table[i].dwOutOctets;
                }
            }
        }
    }
    g_hwData.dlSpeed = FormatSpeed(inBytes >= g_prevNetIn ? inBytes - g_prevNetIn : 0);
    g_hwData.ulSpeed = FormatSpeed(outBytes >= g_prevNetOut ? outBytes - g_prevNetOut : 0);
    g_prevNetIn = inBytes; g_prevNetOut = outBytes;

    CheckAuditRules();
}

// ==========================================
// 界面渲染与托盘控制
// ==========================================
void DrawOverlay(HDC hdc) {
    std::ostringstream text;
    text << std::fixed << std::setprecision(1);
    text << "CPU: " << g_hwData.cpuUsage << "%  MEM: " << g_hwData.usedMemGB << "GB\n";
    if (g_hasGPU) text << "GPU: " << g_hwData.gpuUtil << "%  TMP: " << g_hwData.gpuTemp << "C\n";
    text << "DN: " << g_hwData.dlSpeed << "\nUP: " << g_hwData.ulSpeed;

    if (g_isTiming) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - g_startTime).count();
        int h = elapsed / 3600;
        int m = (elapsed % 3600) / 60;
        int s = elapsed % 60;
        text << "\nTIME: " << std::setfill('0') << std::setw(2) << h << ":"
             << std::setw(2) << m << ":" << std::setw(2) << s;
    }

    std::string output = text.str();
    HFONT hFont = CreateFontA(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              DEFAULT_PITCH | FF_DONTCARE, "Consolas");
    SelectObject(hdc, hFont);
    SetTextColor(hdc, RGB(0, 255, 255));
    SetBkMode(hdc, TRANSPARENT);
    RECT rect = { 10, 10, 300, 150 };
    DrawTextA(hdc, output.c_str(), -1, &rect, DT_LEFT | DT_NOPREFIX);
    DeleteObject(hFont);
}

void InitTrayIcon(HWND hwnd) {
    g_nid.cbSize = sizeof(NOTIFYICONDATAA);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    lstrcpyA(g_nid.szTip, "WinSentry");
    Shell_NotifyIconA(NIM_ADD, &g_nid);
}

void ShowTrayMenu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);
    HMENU hMenu = CreatePopupMenu();

    AppendMenuW(hMenu, MF_STRING, ID_TRAY_TOGGLE, g_showOverlay ? L"隐藏悬浮窗" : L"显示悬浮窗");
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_TIMER, g_isTiming ? L"停止计时" : L"开始游戏计时");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"退出程序");

    SetForegroundWindow(hwnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_NCHITTEST:
            return HTCAPTION;
        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP) ShowTrayMenu(hwnd);
            return 0;
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_TRAY_TOGGLE) {
                g_showOverlay = !g_showOverlay;
                ShowWindow(hwnd, g_showOverlay ? SW_SHOW : SW_HIDE);
            }
            else if (LOWORD(wParam) == ID_TRAY_TIMER) {
                if (!g_isTiming) {
                    // 开始计时：记录时间，并把窗口高度动态拉伸到 115
                    g_startTime = std::chrono::steady_clock::now();
                    g_isTiming = true;
                    SetWindowPos(hwnd, NULL, 0, 0, 220, 115, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
                } else {
                    // 停止计时：还原标志位，并把窗口高度缩回 90
                    g_isTiming = false;
                    SetWindowPos(hwnd, NULL, 0, 0, 220, 90, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);

                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - g_startTime).count();

                    if (elapsed >= 60) {
                        SYSTEMTIME st;
                        GetLocalTime(&st);
                        char timeStr[64];
                        sprintf_s(timeStr, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

                        std::ofstream file("WinSentry_GameTime.csv", std::ios::app);
                        if (file.is_open()) {
                            file << timeStr << ", SessionDuration(s): " << elapsed << "\n";
                        }
                    }
                    InvalidateRect(hwnd, NULL, TRUE);
                }
            }
            else if (LOWORD(wParam) == ID_TRAY_EXIT) {
                PostQuitMessage(0);
            }
            return 0;
        case WM_TIMER:
            UpdateHardwareData();
            if (g_showOverlay) InvalidateRect(hwnd, NULL, TRUE);
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            FillRect(hdc, &ps.rcPaint, (HBRUSH)GetStockObject(BLACK_BRUSH));
            DrawOverlay(hdc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_DESTROY:
            Shell_NotifyIconA(NIM_DELETE, &g_nid);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    InitHardware();

    const char* className = "WinSentryOverlay";
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className;
    RegisterClassA(&wc);

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    // 初始创建时，默认高度为不计时的 90
    HWND hwnd = CreateWindowExA(
        WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        className, "WinSentry", WS_POPUP,
        screenW - 240, 50, 220, 90,
        NULL, NULL, hInstance, NULL
    );

    SetLayeredWindowAttributes(hwnd, 0, 180, LWA_ALPHA);
    InitTrayIcon(hwnd);

    ShowWindow(hwnd, SW_SHOW);
    SetTimer(hwnd, 1, 1000, NULL);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}