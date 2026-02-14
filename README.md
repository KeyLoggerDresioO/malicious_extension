***

# MalExt – Malicious Extension Scanner

Skrypty PowerShell do wykrywania i usuwania złośliwych rozszerzeń przeglądarek

## 📌 Opis projektu

MalExt to zestaw skryptów PowerShell służących do skanowania, wykrywania, usuwania oraz blokowania złośliwych rozszerzeń przeglądarek.  
Projekt korzysta z publicznej bazy rozszerzeń oznaczonych jako szkodliwe i automatycznie wykonuje odpowiednie działania naprawcze.

Dostępne są **dwie wersje skryptu**, różniące się zakresem obsługiwanych przeglądarek:

***

## ✔️ `malext.ps1` – wersja podstawowa

**Obsługiwane przeglądarki:**

*   Google Chrome
*   Microsoft Edge

**Funkcjonalność:**

*   Skanowanie rozszerzeń u bieżącego oraz wszystkich użytkowników systemu
*   Automatyczne usuwanie znalezionych złośliwych rozszerzeń
*   Blokowanie ich ID w GPO (Chrome/Edge) na Windows
*   Działa na Windows, macOS i Linux (z wyłączeniem funkcji GPO – tylko Windows)

**Dla kogo?**  
Użytkownicy i administratorzy, którzy potrzebują skanować tylko Chrome i Edge.

***

## ✔️ `malext_v2.ps1` – wersja rozszerzona

**Obsługuje wszystko, co wersja podstawowa + dodatkowo:**

### 🆕 Obsługa przeglądarek:

*   Google Chrome
*   Microsoft Edge
*   Opera
*   Opera GX

### 🆕 Zaawansowana remediacja Opery (Windows):

*   automatyczne zabijanie procesów
*   cicha deinstalacja (`opera.exe --uninstall --runimmediately --deleteuserprofile=1`)
*   usuwanie profili i katalogów
*   cicha reinstalacja (winget lub instalator Opery)

**Dla kogo?**  
Środowiska, gdzie wymagane jest pełne wsparcie Opery / Opera GX i twarda remediacja.

***

## 🔧 Wymagania

*   PowerShell 5.1 (Windows) lub PowerShell 7+ (dowolny system)
*   Uprawnienia administratora wymagane do:
    *   usuwania rozszerzeń wszystkich użytkowników
    *   zmian GPO (Chrome/Edge)
    *   deinstalacji/reinstalacji Opery

***

## ▶️ Jak uruchomić (malext.ps1 / malext_v2.ps1)

### CMD (malext.ps1):

```cmd
Powershell.exe -ExecutionPolicy Bypass -Command Start-Transcript -Path "$env:ProgramData\ESET\RemoteAdministrator\Agent\EraAgentApplicationData\Logs\MalExt_Scan.txt"; "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"; "$url = 'https://raw.githubusercontent.com/KeyLoggerDresioO/malicious_extension/refs/heads/main/malext.ps1'"; "$tmp = Join-Path $env:TEMP 'malext_scan.ps1'"; "Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing"; "& $tmp"; "Remove-Item $tmp -Force -ErrorAction SilentlyContinue"; Stop-Transcript
```

### CMD (malext_v2.ps1):

```cmd
Powershell.exe -ExecutionPolicy Bypass -Command Start-Transcript -Path "$env:ProgramData\ESET\RemoteAdministrator\Agent\EraAgentApplicationData\Logs\MalExt_Scan.txt"; "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"; "$url = 'https://raw.githubusercontent.com/KeyLoggerDresioO/malicious_extension/refs/heads/main/malext_v2.ps1'"; "$tmp = Join-Path $env:TEMP 'malext_scan.ps1'"; "Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing"; "& $tmp"; "Remove-Item $tmp -Force -ErrorAction SilentlyContinue"; Stop-Transcript
```

***

## 📄 Licencja

Projekt udostępniany na licencji **MIT**.

***
