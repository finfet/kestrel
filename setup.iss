; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

#define AppName "Kestrel CLI"
#define AppVersion "1.0.1"
#define InstallerVersion "1.0.1.0"
#define AppPublisher "Kestrel Developers"
#define AppURL "https://getkestrel.com"
#define AppExeName "kestrel.exe"

[Setup]
; NOTE: The value of AppId uniquely identifies this application. Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{4917E236-8B10-497E-9D48-D530AE55B46A}
AppName={#AppName}
AppVersion={#AppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
VersionInfoVersion={#InstallerVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\KestrelCLI
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=LICENSE.txt
; Remove the following line to run in administrative install mode (install for all users.)
PrivilegesRequired=lowest
OutputDir=build\wininstaller
OutputBaseFilename=kestrel-cli-setup-v{#AppVersion}-x64
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "build\{#AppExeName}"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "THIRD-PARTY-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Tasks]
Name: envPath; Description: "Add program to user path"

[Code]
{ Procedures for adding to Path environment }
const EnvironmentKey = 'Environment';

procedure EnvAddPath(Path: string);
var
    Paths: string;
begin
    { Retrieve current path (use empty string if entry not exists) }
    if not RegQueryStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths)
    then Paths := '';

    { Skip if string already found in path }
    if Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(Paths) + ';') > 0 then exit;

    { App string to the end of the path variable }
    Paths := Paths + ';' + Path + ';'

    { Overwrite (or create if missing) path environment variable }
    if RegWriteStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths)
    then Log(Format('The [%s] added to PATH: [%s]', [Path, Paths]))
    else Log(Format('Error while adding the [%s] to PATH: [%s]', [Path, Paths]));
end;

procedure EnvRemovePath(Path: string);
var
    Paths: string;
    P: Integer;
begin
    { Skip if registry entry not exists }
    if not RegQueryStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths) then
        exit;

    { Skip if string not found in path }
    P := Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(Paths) + ';');
    if P = 0 then exit;

    { Update path variable }
    Delete(Paths, P - 1, Length(Path) + 1);

    { Overwrite path environment variable }
    if RegWriteStringValue(HKEY_CURRENT_USER, EnvironmentKey, 'Path', Paths)
    then Log(Format('The [%s] removed from PATH: [%s]', [Path, Paths]))
    else Log(Format('Error while removing the [%s] from PATH: [%s]', [Path, Paths]));
end;

{ Check user selection and call to add to path }

procedure CurStepChanged(CurStep: TSetupStep);
begin
    if (CurStep = ssPostInstall) and WizardIsTaskSelected('envPath')
     then EnvAddPath(ExpandConstant('{app}') + '\bin');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
    if CurUninstallStep = usPostUninstall
    then EnvRemovePath(ExpandConstant('{app}') + '\bin');
end;
