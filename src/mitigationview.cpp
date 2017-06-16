//
// mitigationsview.cpp
//
// Simple tool to show the process mitigations policy
//

#include "stdafx.h"

// stringification
#define xstr(s) str(s)
#define str(s) #s

void print_error(const char *desc, DWORD errcode) {
    LPTSTR errorText = NULL;

    FormatMessage(
        // use system message tables to retrieve error text
        FORMAT_MESSAGE_FROM_SYSTEM
        // allocate buffer on local heap for error text
        |FORMAT_MESSAGE_ALLOCATE_BUFFER
        // Important! will fail otherwise, since we're not
        // (and CANNOT) pass insertion parameters
        |FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
        errcode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&errorText,  // output
        0, // minimum size for output buffer
        NULL);   // arguments - see note

    if (errorText != NULL) {
        if (desc == NULL) desc = "Error";
        if (errorText[strlen(errorText)-1] == '\n') errorText[strlen(errorText)-1] = '\0';
        if (errorText[strlen(errorText)-1] == '\r') errorText[strlen(errorText)-1] = '\0';
        fprintf(stderr, "%s: %08X: %s\n", desc, errcode, errorText);
        // release memory allocated by FormatMessage()
        LocalFree(errorText);
    }
}

#define GET_MITIGATION(proc, p, b, s) \
    if (!GetProcessMitigationPolicy((proc), (p), (b), (s))) { \
        if (0) { print_error(str(p), GetLastError()); } \
    } else

void print_mitigations(HANDLE hProc) {

    PROCESS_MITIGATION_DEP_POLICY                       dep = {0};
    PROCESS_MITIGATION_ASLR_POLICY                      aslr = {0};
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY       strict_handle_check = {0};
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY       system_call_disable = {0};
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY   extension_point_disable = {0};
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY        control_flow_guard = { 0 };
    PROCESS_MITIGATION_FONT_DISABLE_POLICY              font_disable_policy = { 0 };
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY              dynamic_code_policy = { 0 };

    GET_MITIGATION(hProc, ProcessDEPPolicy, &dep, sizeof(dep)) {
        printf("ProcessDEPPolicy\n");
        printf(" Enable                                     %u\n", dep.Enable);
        printf(" DisableAtlThunkEmulation                   %u\n", dep.DisableAtlThunkEmulation);
    }

    GET_MITIGATION(hProc, ProcessASLRPolicy, &aslr, sizeof(aslr)) {
        printf("ProcessASLRPolicy\n");
        printf(" EnableBottomUpRandomization                %u\n", aslr.EnableBottomUpRandomization);
        printf(" EnableForceRelocateImages                  %u\n", aslr.EnableForceRelocateImages);
        printf(" EnableHighEntropy                          %u\n", aslr.EnableHighEntropy);
        printf(" DisallowStrippedImages                     %u\n", aslr.DisallowStrippedImages);
    }

    GET_MITIGATION(hProc, ProcessStrictHandleCheckPolicy, &strict_handle_check, sizeof(strict_handle_check)) {
        printf("ProcessStrictHandleCheckPolicy\n");
        printf(" RaiseExceptionOnInvalidHandleReference     %u\n", strict_handle_check.RaiseExceptionOnInvalidHandleReference);
        printf(" HandleExceptionsPermanentlyEnabled         %u\n", strict_handle_check.HandleExceptionsPermanentlyEnabled);
    }

    GET_MITIGATION(hProc, ProcessSystemCallDisablePolicy, &system_call_disable, sizeof(system_call_disable)) {
        printf("ProcessSystemCallDisablePolicy\n");
        printf(" DisallowWin32kSystemCalls                  %u\n", system_call_disable.DisallowWin32kSystemCalls);
    }

    GET_MITIGATION(hProc, ProcessExtensionPointDisablePolicy, &extension_point_disable, sizeof(extension_point_disable)) {
        printf("ProcessExtensionPointDisablePolicy\n");
        printf(" DisableExtensionPoints                     %u\n", extension_point_disable.DisableExtensionPoints);
    }

    GET_MITIGATION(hProc, ProcessControlFlowGuardPolicy, &control_flow_guard, sizeof(control_flow_guard)) {
        printf("ProcessControlFlowGuardPolicy\n");
        printf(" EnableControlFlowGuard                     %u\n", control_flow_guard.EnableControlFlowGuard);
        printf(" EnableExportSuppression                    %u\n", control_flow_guard.EnableExportSuppression);
        printf(" StrictMode                                 %u\n", control_flow_guard.StrictMode);
    }

    GET_MITIGATION(hProc, ProcessFontDisablePolicy, &font_disable_policy, sizeof(font_disable_policy)) {
        printf("ProcessFontDisablePolicy\n");
        printf(" DisableNonSystemFonts                      %u\n", font_disable_policy.DisableNonSystemFonts);
        printf(" AuditNonSystemFontLoading                  %u\n", font_disable_policy.AuditNonSystemFontLoading);
    }

    GET_MITIGATION(hProc, ProcessDynamicCodePolicy, &dynamic_code_policy, sizeof(dynamic_code_policy)) {
        printf("ProcessDynamicCodePolicy\n");
        printf(" ProhibitDynamicCode                        %u\n", dynamic_code_policy.ProhibitDynamicCode);
        printf(" AllowThreadOptOut                          %u\n", dynamic_code_policy.AllowThreadOptOut);
        printf(" AllowRemoteDowngrade                       %u\n", dynamic_code_policy.AllowRemoteDowngrade);
    }
}

void usage(const char *p) {
    printf("usage: %s <pid> [<pid> [...]]\n", p);
}

int main(int argc, char* argv[]) {
    DWORD pid = 0;
    HANDLE hProc;

    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; i++) {
        pid = strtoul(argv[i], NULL, 0);
        if (pid == 0) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
        if (hProc == NULL) {
            print_error("OpenProcess", GetLastError());
            return EXIT_FAILURE;
        }

        printf("\nProcess %d mitigations: \n", pid);
        print_mitigations(hProc);

        CloseHandle(hProc);
    }
    return EXIT_SUCCESS;
}
