program main;

  {$APPTYPE CONSOLE}

uses
  MicrosoftApiAuthenticator,
  testModule,
  key_press_helper,
  System.Classes,
  System.SysUtils;

var
  Authenticator: TMsAuthenticator;
  module: TtestModule;
begin
  Authenticator := TMsAuthenticator.Create(
    ATDelegated,
    TMsClientInfo.Create(
      'f9af2c9b-466f-42b5-b948-9d17731f8fc2',
      'e8ab62a8-c0cb-457c-9402-6caa938909c3',
      ['User.Read.All', 'User.ReadWrite'],
      TRedirectUri.Create(8080, 'MyApp'),
      TMsTokenStorege.CreateEmpty
    ),
    TMsClientEvents.Create(
    procedure(ResponseInfo: THttpServerResponse)
    begin
      ResponseInfo.ContentStream := TStringStream.Create('<title>Login Succes</title>This tab can be closed now :)');
    end,
    procedure(Error: TMsError)
    begin
      Writeln(Format(
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
      Cancel := KeyPressed(0);
    end
    )
  );

  module := TtestModule.Create(Authenticator);

  Writeln(module.AccessToken);

  module.raiseError();

  module.Free;

  Authenticator.Free;

end.
