; K3 SIEM native agent installer.
;
; Silent install:  k3-agent-setup.exe /S /SIEMURL=https://siem.example.com /APIKEY=xxxxx
; Interactive install prompts for the same two values.
;
; What this installer does (service-install-only scope, per plan — it does not touch OS audit
; policy): copies k3-agent.exe + config.yaml into Program Files, registers it as an
; auto-starting Windows Service via sc.exe, opens one outbound firewall rule for it, and starts
; the service. Uninstall reverses all of that.
!include "MUI2.nsh"
!include "FileFunc.nsh"

Name "K3 SIEM Agent"
OutFile "k3-agent-setup.exe"
InstallDir "$PROGRAMFILES64\K3Agent"
RequestExecutionLevel admin

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Var SiemUrl
Var ApiKey

Function .onInit
  StrCpy $SiemUrl "http://localhost:3001"
  StrCpy $ApiKey ""

  ${GetParameters} $R0
  ${GetOptions} $R0 "/SIEMURL=" $R1
  IfErrors +2 0
    StrCpy $SiemUrl $R1
  ${GetOptions} $R0 "/APIKEY=" $R1
  IfErrors +2 0
    StrCpy $ApiKey $R1

  ; Interactive (non-/S) installs without an API key on the command line get a warning — the
  ; service will still install but refuses to start with an empty key (see main.cpp), so this
  ; is a heads-up, not a hard stop.
  ${GetOptions} $R0 "/S" $R2
  IfErrors 0 skip_warning
    StrCmp $ApiKey "" 0 skip_warning
      MessageBox MB_OK|MB_ICONEXCLAMATION "No API key was provided. Edit config.yaml in the install directory and restart the K3Agent service after installing."
    skip_warning:
FunctionEnd

Section "Install"
  SetOutPath "$INSTDIR"
  File "..\..\build\k3-agent.exe"

  ; config.yaml written from the install-time SIEM URL / API key rather than shipping a
  ; template that would need manual editing post-install.
  FileOpen $0 "$INSTDIR\config.yaml" w
  FileWrite $0 "siem_url: $SiemUrl$\r$\n"
  FileWrite $0 "api_key: $ApiKey$\r$\n"
  FileWrite $0 "agent_version: $\"1.0.0-cpp$\"$\r$\n"
  FileWrite $0 "collection_interval: 10$\r$\n"
  FileWrite $0 "heartbeat_interval: 30$\r$\n"
  FileWrite $0 "batch_size: 50$\r$\n"
  FileWrite $0 "vuln_scan_enabled: true$\r$\n"
  FileClose $0

  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Service registration — auto-start, restart on failure. binPath points at the same exe
  ; with --service so it goes through the ServiceMain dispatcher path (see src/main.cpp)
  ; instead of running as a plain foreground process.
  ExecWait 'sc.exe create K3Agent binPath= "\"$INSTDIR\k3-agent.exe\" --service \"$INSTDIR\config.yaml\"" start= auto DisplayName= "K3 SIEM Agent"'
  ExecWait 'sc.exe description K3Agent "Collects logs, inventory, and missing-patch data for K3 SIEM."'
  ExecWait 'sc.exe failure K3Agent reset= 86400 actions= restart/60000/restart/60000/restart/60000'

  ; Outbound-only rule so the agent can reach the SIEM backend; nothing is opened for inbound
  ; traffic, matching the "service install only, no broader policy changes" scope.
  ExecWait 'netsh advfirewall firewall add rule name="K3 SIEM Agent (outbound)" dir=out program="$INSTDIR\k3-agent.exe" action=allow enable=yes'

  ExecWait 'sc.exe start K3Agent'
SectionEnd

Section "Uninstall"
  ExecWait 'sc.exe stop K3Agent'
  ExecWait 'sc.exe delete K3Agent'
  ExecWait 'netsh advfirewall firewall delete rule name="K3 SIEM Agent (outbound)"'
  Delete "$INSTDIR\k3-agent.exe"
  Delete "$INSTDIR\config.yaml"
  Delete "$INSTDIR\k3-agent-cpp-state.json"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
