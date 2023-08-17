# Usage

Depending on weather you want to authenticate with a Microsoft Account or with a client secret, the Create method of the `TMsAuthenticator` class has to be called with different parameters.

## 1 Microsoft Account (`DELEGATED`)

```delphi
var
  Authenticator: TMsAuthenticator;
begin
  Authenticator := TMsAuthenticator.Create(
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
  );

  // Use the authenticator
  .
  .
  .

  // Free the authenticator
  Authenticator.Free;
end;
```

Storing the token is done automatically (on windows its at `%appdata%\<exe name or specified name>\token.bin`).

## 2 Client Secret (`APPLICATION`)

```delphi
var
  Authenticator: TMsAuthenticator;
begin
  Authenticator := TMsAuthenticator.Create(
    ATDelegated,
    TMsClientInfo.Create(
      '<YOUR TENANT ID>',
      '<YOUR CLIENT ID>',
      '<YOUR CLIENT SECRET>',
      ['User.Read', '<SCOPES>'],
      TRedirectUri.Create(8080, 'MyApp'),  // YOUR REDIRECT URI (it must be localhost though)
    ),
    TMsClientEvents.Create(
    procedure(ResponseInfo: THttpServerResponse)
    begin
      ResponseInfo.ContentStream := TStringStream.Create('<title>Succes</title>This tab can be closed now :)');  // YOUR SUCCESS PAGE, do whatever you want here
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

  // Use the authenticator
  .
  .
  .

  // Free the authenticator
  Authenticator.Free;
end;
```

## 3 Adding Modules

You can create your own modules by inheriting from TMsModule and implementing the abstract methods.

```delphi
unit MyModule;
interface

uses
  MicrosoftApiAuthenticator,
  System.Net.HttpClient,
  System.Net.URLClient;

TMsMyAddon = class(TMsAdapter)
private
public
  procedure DoSomething;  // example method
end;

implementation

procedure TMsMyAddon.DoSomething;
var
  AResponse: IHTTPResponse;
  AError: TMsError;
  AJsonResponse: TJSONValue;
  AJsonError: TJsonValue;
  AString: string;
begin
  // get me
  AResponse := self.Http.Get('https://graph.microsoft.com/v1.0/me', nil, [TNameValuePair.Create('Authentication', self.Token)]);

  if AResponse.StatusCode <> 200 then
  begin
    // handle an error
    AError.HTTPStatusCode := AResponse.StatusCode;
    AError.HTTPStatusText := AResponse.StatusText;
    AError.HTTPurl := AResponse.URL.ToString;
    AError.HTTPMethod := AResponse.MethodString;
    AError.HTTPreq_Header := AResponse.Headers;
    AError.HTTPres_header := AResponse.Headers;
    AError.HTTPerror_data := AResponse.ContentAsString;

    // try to parse the error message and description
    AJsonResponse := TJSONValue.ParseJSONValue(ARes.ContentAsString(TEncoding.UTF8));
    if AJsonResponse <> nil then
    begin
      if AJsonResponse.TryGetValue<TJsonValue>('error', AJsonError) then
      begin
        AJsonError.TryGetValue<string>('code', AError.HTTPerror_name);
        AJsonError.TryGetValue<string>('message', AError.HTTPerror_description);
      end;
      AJsonResponse.Free;
    end;
  end
  else
  begin
    // Do something with the response

    // Parse the response
    AJsonResponse := TJSONValue.ParseJSONValue(ARes.ContentAsString(TEncoding.UTF8));
    if AJsonResponse <> nil then
    begin
      // try to get the display name
      if AJsonResponse.TryGetValue<string>('displayName', AString) then
        Writeln(AString);
      AJsonResponse.Free;
    end;
  end;
end;

end.
```

Things like Throttling and Rate Limiting are **NOT** handled by the library, you have to do that yourself.

## 4 Scopes

A list of scopes can be found [here](https://learn.microsoft.com/en-us/graph/permissions-reference).

`offline_access` scope gets added automatically.
