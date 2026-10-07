/* wineprobe: measure the answers Wine gives to the static (history-independent) queries rct.exe
 * makes, including output buffers that an API-call trace does not show in full. Run under the
 * oracle's environment (lift/test/host/probe/run-probe.sh: fresh copy of the pristine prefix,
 * private 1024x768x24 Xvfb, started from the game directory). The output (text, one fact per
 * line) is evidence for the documented constants in lift/host/wine-answers.js; the host never
 * reads it at run time.  Build: i686-w64-mingw32-gcc -O1 -o wineprobe.exe wineprobe.c -lwinmm -lgdi32 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>
#include <string.h>

static void hexdump(const char *tag, const void *p, int n)
{
    const unsigned char *b = p;
    printf("%s", tag);
    for (int i = 0; i < n; i++) printf(" %02x", b[i]);
    printf("\n");
}

typedef struct { DWORD dwSize, dwFlags, dwHeight, dwWidth; LONG lPitch; DWORD rest[22]; } DDSD; /* 108 bytes */
static int nmodes;
static HRESULT WINAPI enum_cb(DDSD *d, void *ctx)
{
    (void)ctx;
    char tag[32]; snprintf(tag, sizeof tag, "ddmode %d", nmodes++);
    hexdump(tag, d, 108);
    return 1;
}

int main(void)
{
    setvbuf(stdout, NULL, _IOFBF, 1 << 20);
    /* ---- version and system */
    printf("GetVersion %#lx\n", GetVersion());
    OSVERSIONINFOA ov; memset(&ov, 0xCC, sizeof ov); ov.dwOSVersionInfoSize = sizeof ov;
    printf("GetVersionExA ret %d\n", GetVersionExA(&ov));
    hexdump("OSVERSIONINFOA", &ov, sizeof ov);
    SYSTEM_INFO si; memset(&si, 0xCC, sizeof si); GetSystemInfo(&si);
    hexdump("SYSTEM_INFO", &si, sizeof si);
    for (int i = 0; i < 48; i++) printf("IsProcessorFeaturePresent %d %d\n", i, IsProcessorFeaturePresent(i));
    printf("GetACP %u GetOEMCP %u\n", GetACP(), GetOEMCP());
    CPINFO cp; memset(&cp, 0xCC, sizeof cp);
    printf("GetCPInfo(CP_ACP) ret %d\n", GetCPInfo(CP_ACP, &cp)); hexdump("CPINFO", &cp, sizeof cp);
    printf("GetCPInfo(1252) ret %d\n", GetCPInfo(1252, &cp)); hexdump("CPINFO1252", &cp, sizeof cp);
    /* ---- process startup */
    printf("GetCommandLineA [%s]\n", GetCommandLineA());
    char mf[MAX_PATH]; memset(mf, 0, sizeof mf);
    printf("GetModuleFileNameA ret %lu [%s]\n", GetModuleFileNameA(NULL, mf, sizeof mf), mf);
    printf("GetModuleHandleA(NULL) %p\n", GetModuleHandleA(NULL));
    STARTUPINFOA st; memset(&st, 0xCC, sizeof st); GetStartupInfoA(&st);
    hexdump("STARTUPINFOA", &st, sizeof st);
    printf("STARTUPINFOA.lpDesktop [%s] lpTitle [%s] lpReserved [%s]\n", st.lpDesktop ? st.lpDesktop : "(null)",
           st.lpTitle ? st.lpTitle : "(null)", st.lpReserved ? st.lpReserved : "(null)");
    for (int i = -10; i >= -12; i--) {
        HANDLE h = GetStdHandle((DWORD)i);
        printf("GetStdHandle %d %p GetFileType %lu\n", i, h, GetFileType(h));
    }
    /* ---- NLS, per code-page-1252 byte, as the C runtime's _setmbcp/__crtLCMapStringA use them */
    for (int c = 0; c < 256; c++) {
        char ch = (char)c; WCHAR w = 0, u = 0, l = 0; WORD t1 = 0, t2 = 0, t3 = 0;
        int n = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, &ch, 1, &w, 1);
        int nu = LCMapStringW(0, LCMAP_UPPERCASE, &w, 1, &u, 1);
        int nl = LCMapStringW(0, LCMAP_LOWERCASE, &w, 1, &l, 1);
        GetStringTypeW(CT_CTYPE1, &w, 1, &t1); GetStringTypeW(CT_CTYPE2, &w, 1, &t2); GetStringTypeW(CT_CTYPE3, &w, 1, &t3);
        char bu = 0, bl = 0; BOOL du = 0, dl = 0;
        int ru = WideCharToMultiByte(CP_ACP, 0, &u, 1, &bu, 1, NULL, &du);
        int rl = WideCharToMultiByte(CP_ACP, 0, &l, 1, &bl, 1, NULL, &dl);
        printf("nls %02x mb %d %04x up %d %04x lo %d %04x t1 %04x t2 %04x t3 %04x wcup %d %02x %d wclo %d %02x %d\n",
               c, n, w, nu, u, nl, l, t1, t2, t3, ru, (unsigned char)bu, du, rl, (unsigned char)bl, dl);
    }
    /* ---- USER / GDI */
    for (int i = 0; i < 100; i++) printf("GetSystemMetrics %d %d\n", i, GetSystemMetrics(i));
    for (int i = 0; i < 3; i++) printf("GetKeyboardType %d %d\n", i, GetKeyboardType(i));
    int mouse[3] = {-1, -1, -1};
    printf("SPI_GETMOUSE ret %d %d %d %d\n", SystemParametersInfoA(SPI_GETMOUSE, 0, mouse, 0), mouse[0], mouse[1], mouse[2]);
    HDC dc = GetDC(NULL);
    for (int i = 0; i < 128; i += 2) printf("GetDeviceCaps %d %d\n", i, GetDeviceCaps(dc, i));
    printf("GetSystemPaletteUse %u\n", GetSystemPaletteUse(dc));
    ReleaseDC(NULL, dc);
    /* ---- DirectDraw (as rct.exe: LoadLibraryA + GetProcAddress, DirectDrawCreate(NULL), EnumDisplayModes(0, NULL)) */
    HMODULE dd = LoadLibraryA("DDRAW.DLL");
    printf("LoadLibraryA(DDRAW.DLL) %p\n", dd);
    HRESULT (WINAPI *ddc)(GUID *, void **, void *) = (void *)GetProcAddress(dd, "DirectDrawCreate");
    void *ddo = NULL; HRESULT hr = ddc(NULL, &ddo, NULL);
    printf("DirectDrawCreate %#lx\n", (unsigned long)hr);
    if (hr == 0) {
        void **vt = *(void ***)ddo;
        HRESULT (WINAPI *edm)(void *, DWORD, void *, void *, void *) = vt[8];
        hr = edm(ddo, 0, NULL, NULL, enum_cb);
        printf("EnumDisplayModes ret %#lx modes %d\n", (unsigned long)hr, nmodes);
    }
    /* ---- music */
    UINT nd = midiOutGetNumDevs();
    printf("midiOutGetNumDevs %u\n", nd);
    for (int i = -1; i < (int)nd; i++) {
        MIDIOUTCAPSA mc; memset(&mc, 0xCC, sizeof mc);
        MMRESULT r = midiOutGetDevCapsA((UINT)i, &mc, sizeof mc);
        printf("midiOutGetDevCapsA %d ret %u\n", i, r); hexdump("MIDIOUTCAPSA", &mc, sizeof mc);
    }
    DWORD vol = 0xCCCCCCCC; MMRESULT r = midiOutGetVolume((HMIDIOUT)(UINT_PTR)-1, &vol);
    printf("midiOutGetVolume(-1) ret %u vol %#lx\n", r, vol);
    printf("timeBeginPeriod(1) %u\n", timeBeginPeriod(1));
    char ret[256];
    printf("mciSendStringA(close all) %lu\n", mciSendStringA("close all", ret, 0, NULL));
    printf("mciSendStringA(open) %lu\n", mciSendStringA("open C:\\x.mid type sequencer alias MUSIC", ret, 0, NULL));
    fflush(stdout);
    return 0;
}
