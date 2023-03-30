# MicrosoftApiAuthentication

This is a simple Delphi-module to authenticate with Microsoft APIs using OAuth2.0.

## Installation

Just take the MicrosoftApiAuthentication.pas file and include it in your project.

## Usage

Depending on weather you want to authenticate with a Microsoft Account or with a client secret, the Create method of the TMsAuthenticator class has to be called with different parameters.

### Microsoft Account (DELEGATED)

```delphi
<Var> := TMsAuthenticator.Create(
    ATDelegated,
    TMsClientInfo.Create(
      '<YOUR TENANT ID>',
      '<YOUR CLIENT ID>',
      ['User.Read', '<SCOPES>'],
      TRedirectUri.Create(8080, 'MyApp'), // YOUR REDIRECT URI (it must be localhost though)
      TMsTokenStorege.CreateEmpty
    ),
    TMsClientEvents.Create(
    procedure(ResponseInfo: THttpServerResponse)
    begin
      ResponseInfo.ContentStream := TStringStream.Create('<title>Login Succes</title>This tab can be closed now :)');  // YOUR SUCCESS PAGE, do whatever you want here
    end,
    procedure(Error: TMsError)
    begin
      Writeln(Format(  // A premade error message, do whatever you want here
        ''
        + '%sStatus: . . . . . %d : %s'
        + '%sErrorName:  . . . %s'
        + '%sErrorDescription: %s'
        + '%sUrl:  . . . . . . %s %s'
        + '%sData: . . . . . . %s',
        [
          sLineBreak, error.HTTPStatusCode, error.HTTPStatusText,
          sLineBreak, error.HTTPerror_name,
          sLineBreak, error.HTTPerror_description,
          sLineBreak, error.HTTPMethod, error.HTTPurl,
          sLineBreak, error.HTTPerror_data
        ]
      ));
    end,
    procedure(out Cancel: boolean)
    begin
      Cancel := KeyPressed(0);  // Cancel the authentication if a key is pressed
      sleep(0); // if you refresh app-messages here you dont need the sleep
      // Application.ProcessMessages;
    end
    )
  );
```

### Client Secret (APPLICATION)

```delphi
<Var> := TMsAuthenticator.Create(
    ATDelegated,
    TMsClientInfo.Create(
      '<YOUR TENANT ID>',
      '<YOUR CLIENT ID>',
      '<YOUR CLIENT SECRET>',
      ['User.Read', '<SCOPES>'],
      TRedirectUri.Create(8080, 'MyApp'), // YOUR REDIRECT URI (it must be localhost though)
    ),
    TMsClientEvents.Create(
    procedure(ResponseInfo: THttpServerResponse)
    begin
      ResponseInfo.ContentStream := TStringStream.Create('<title>Login Succes</title>This tab can be closed now :)');  // YOUR SUCCESS PAGE, do whatever you want here
    end,
    procedure(Error: TMsError)
    begin
      Writeln(Format(  // A premade error message, do whatever you want here
        ''
        + '%sStatus: . . . . . %d : %s'
        + '%sErrorName:  . . . %s'
        + '%sErrorDescription: %s'
        + '%sUrl:  . . . . . . %s %s'
        + '%sData: . . . . . . %s',
        [
          sLineBreak, error.HTTPStatusCode, error.HTTPStatusText,
          sLineBreak, error.HTTPerror_name,
          sLineBreak, error.HTTPerror_description,
          sLineBreak, error.HTTPMethod, error.HTTPurl,
          sLineBreak, error.HTTPerror_data
        ]
      ));
    end,
    procedure(out Cancel: boolean)
    begin
      Cancel := KeyPressed(0);  // Cancel the authentication if a key is pressed
      sleep(0); // if you refresh app-messages here you dont need the sleep
      // Application.ProcessMessages;
    end
    )
  );
```

### Adding Modules

You can create your own modules by inheriting from TMsModule and implementing the abstract methods.

```delphi
unit MyModule;
interface

uses
  MicrosoftApiAuthenticator;

TMsMyAddon = class(TMsAdapter)
private
public
  constructor Create(const Authenticator: TMsAuthenticator);
end;

implementation

constructor TMsMyAddon.Create(const Authenticator: TMsAuthenticator);
begin
  inherited Create(Authenticator);
end;

end.
```
