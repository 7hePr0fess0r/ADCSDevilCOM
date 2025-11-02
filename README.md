# ADCSDevilCOM
A C# tool for requesting certificates from ADCS using DCOM over SMB. This tool allows you to remotely request X.509 certificates from CA server using the MS-WCCE protocol over DCOM and It bypasses the traditional endpoint mapper requirement by using SMB directly.

> [!WARNING]
> Use only in environments where you have explicit authorization. Unauthorized use may be illegal.

## What This Tool Can Do

- 📋 **Request and Export certificates remotely** via DCOM/SMB
- 📋 **Add Subject Alternative Names** (UPN/DNS) for ESC1 exploitation
- 📋 **Retrieve pending certificates with CA Manager Approval** by request ID

### Attack Scenarios
- 💥 **ESC1**: Request certificates with arbitrary UPNs to impersonate other users
- 💥 **ESC6**: Abuse any template when EDITF_ATTRIBUTESUBJECTALTNAME2 is set
- 💥 **Persistence**: Create long-lived certificates for backdoor access

---

## Build

```bash
# Clone or download the tool
git clone https://github.com/7hePr0fess0r/ADCSDevilCOM
cd ADCSDevilCOM

# Build (For testing I used .NET 9 SDK)
dotnet build

# Publish (optional)
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

---

## Usage

### Command-Line Syntax

```bash
ADCSDevilCOM.exe -target dc01.corp.local -ca DC01-CA -template VulnerableTemplate [OPTIONS]
```

---

## Technical Details
See the [Technical Details]() for how ADCSDevilCOM works.

---

## Usecases
See the [Usecases]() for how ADCSDevilCOM can be used.

