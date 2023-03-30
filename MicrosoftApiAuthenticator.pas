unit MicrosoftApiAuthenticator;

interface

uses
  System.Net.HttpClient,
  System.Net.URLClient,
  System.NetConsts,
  System.NetEncoding,
  System.JSON,
  System.SysUtils,
  System.DateUtils,
  System.StrUtils,
  System.Classes,
  System.IOUtils,
  {$IFDEF MSWINDOWS}
  Winapi.ShellAPI,
  Windows,
  {$ELSEIF POSIX}
  Posix.Stdlib,
  {$ENDIF}
  IdHTTPServer, IdContext, IdCustomHTTPServer, IdSocketHandle, IdURI, IdCustomTCPServer;

type
  TMsError = record
    HTTPStatusCode: integer;
    HTTPStatusText: string;
    HTTPurl: string;
    HTTPMethod: string;
    HTTPreq_Header: TNetHeaders;
    HTTPres_header: TNetHeaders;
    HTTPerror_data: string;
    HTTPerror_name: string;
    HTTPerror_description: string;
    INTERNALerror_name: string;
    INTERNALerror_message: string;
    class operator Initialize(out Dest: TMsError);
  end;


  THttpServerResponse = TIdHTTPResponseInfo;
  TRedirectUri = record
  public const
    Transport = 'http://';
    IP = '127.0.0.1';
    Domain = 'localhost';
  private
    function GetRedirectUri: string;
  public
    Port: word;
    URL: string;
    class function Create(Port: word; URL: string): TRedirectUri; static;
  end;

  TMsTokenStorege = record
  private const
    FileName = 'MicrosoftAzureAuthentication.bin';
  private type
    TToken = record
      token: string;
      scope: string;
      tenant: string;
      redirectUri: string;
    end;
  private
    Token: TToken;
    AppName: string;
    function BuildFilename(): string;
    procedure store();
    function load(): boolean;
  public
    class function Create(AppName: string): TMsTokenStorege; static;
    class function CreateEmpty: TMsTokenStorege; static;
  end;

  TMsClientInfo = record
  private type
    TScope = record
      scopes: TArray<string>;
      function makeScopeString: string;
    end;
  private
    Tenant,
    ClientId,
    ClientSecret: string;
    Scope: TScope;
    RedirectUri: TRedirectUri;
    TokenStorage: TMsTokenStorege;
    function CheckToken: boolean;
  public
    class function Create(Tenant, ClientId: string; Scope: TArray<string>; RedirectUri: TRedirectUri; TokenStorage: TMsTokenStorege): TMsClientInfo; overload; static;
    class function Create(Tenant, ClientId, ClientSecret: string; Scope: TArray<string>; RedirectUri: TRedirectUri): TMsClientInfo; overload; static;
  end;

  TMsClientEvents = record
  public type
    // EVENTS
    TOnPageOpen = reference to procedure(ResponseInfo: THttpServerResponse);
    TOnRequestError = reference to procedure(Error: TMsError);
    TWhileWaitingOnToken = reference to procedure(out Cancel: boolean);
  public
    OnPageOpen: TOnPageOpen;
    OnRequestError: TOnRequestError;
    WhileWaitingOnToken: TWhileWaitingOnToken;
    class function Create(OnPageOpen: TOnPageOpen; OnRequestError: TOnRequestError; WhileWaitingOnToken: TWhileWaitingOnToken): TMsClientEvents; static;
  end;

  TMsAuthenticator = class
  private type
    TOnRequestError = TMsClientEvents.TOnRequestError;
  public type
    TAthenticatorType = (ATDelegated, ATDeamon);
  private
    FAuthenticatorType: TAthenticatorType;
    // main Vars
    FHttpClient: THTTPClient;

    FClientInfo: TMsClientInfo;
    FEvents: TMsClientEvents;
    function FGetToken: string; virtual; abstract;
    function FForceRefresh: string; virtual; abstract;
    function FGetRequestErrorEvent: TOnRequestError; virtual; abstract;
  public
    class function Create(AuthenticatorType: TAthenticatorType; ClientInfo: TMsClientInfo; ClientEvents: TMsClientEvents): TMsAuthenticator; overload;
  end;

  TMsDelegatedAuthenticator = class(TMsAuthenticator)
  private
    // HTTP Vars

    FScope: TMsClientInfo.TScope;

    // Token Vars
    FAccesCode: string;
    FAccesCodeSet: boolean;
    FAccesCodeErrorIsCancel: boolean;
    FAccesCodeErrorOccured: boolean;

    FAccesToken: string;

    FAccesTokenExpiresAt: int64;

    FState: string;


    // HTTPServer Events
    procedure FOnCommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure FOnIdListenException(AThread: TIdListenerThread; AException: Exception);
    procedure FOnIdException(AContext: TIdContext; AException: Exception);
    procedure FOnIdCommandError(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo; AException: Exception);

    // Helper functions
    function FCreateState: string;

    // auth functions
    function FDoUserAuth(): boolean;
    function FDoRefreshToken(): boolean;

    // main functions
    function FGetToken: string; override;
    function FForceRefresh: string; override;

    function FGetRequestErrorEvent: TMsAuthenticator.TOnRequestError; override;
  public
    constructor Create(ClientInfo: TMsClientInfo; ClientEvents: TMsClientEvents);
    destructor Destroy; override;
  end;

  TMsDeamonAuthenticator = class(TMsAuthenticator)
  private

    // HTTP Vars
    FScope: TMsClientInfo.TScope;

    // Token Vars
    FAdminConsentGiven: boolean;
    FAdminConsentErrorOccured: boolean;

    FAccesToken: string;

    FAccesTokenExpiresAt: int64;

    FState: string;


    // HTTPServer Events
    procedure FOnCommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
    procedure FOnIdListenException(AThread: TIdListenerThread; AException: Exception);
    procedure FOnIdException(AContext: TIdContext; AException: Exception);
    procedure FOnIdCommandError(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo; AException: Exception);

    // Helper functions
    function FCreateState: string;

    // auth functions
    function FDoAdminAuth(): boolean;
    function FDoGetNewToken(): boolean;

    // main functions
    function FGetToken: string; override;
    function FForceRefresh: string; override;

    function FGetRequestErrorEvent: TMsAuthenticator.TOnRequestError; override;
  public
    constructor Create(ClientInfo: TMsClientInfo; ClientEvents: TMsClientEvents);
    destructor Destroy; override;
  end;


  TMsAdapter = class abstract
  public type
    TAthenticatorType = TMsAuthenticator.TAthenticatorType;
  private type
    TOnRequestError = TMsAuthenticator.TOnRequestError;
  private
    FAuthenticator: TMsAuthenticator;
    function FGetToken: string;
    function FForeRefresh: string;
    function FGetAuthenticatorType: TAthenticatorType;
    function FGetRequestErrorEvent: TOnRequestError;
    function FGetHttpClient: THttpClient;
  protected
    property Token: string read FGetToken;
    property Http: THttpClient read FGetHttpClient;
    property ForceRefresh: string read FForeRefresh;
    property AuthenticatorType: TAthenticatorType read FGetAuthenticatorType;
    property OnRequestError: TOnRequestError read FGetRequestErrorEvent;
  public
    constructor Create(Authenticator: TMsAuthenticator);
  end;

implementation

{ TMsAdTokenStorege }

function TMsTokenStorege.BuildFilename(): string;
begin
  if self.AppName = '' then self.AppName := extractfilename(paramstr(0));
  Result := IncludeTrailingPathDelimiter(IncludeTrailingPathDelimiter(TPath.GetHomePath)+self.AppName)+TMsTokenStorege.FileName;
end;

class function TMsTokenStorege.Create(AppName: string): TMsTokenStorege;
begin
  Result := Default(TMsTokenStorege);
  Result.AppName := AppName;
end;

class function TMsTokenStorege.CreateEmpty: TMsTokenStorege;
begin
  Result := Default(TMsTokenStorege);
end;

function TMsTokenStorege.load(): boolean;
var
  AF: TStringStream;
  Aj: TJsonValue;
begin
  Result := False;
  if FileExists(self.BuildFilename()) then
  begin
    // Open File And create stream
    AF := TStringStream.Create;
    try
      AF.LoadFromFile(self.BuildFilename());
      // read data
      Aj := TJSONValue.ParseJSONValue(AF.ReadString(Af.Size));

      Aj.TryGetValue<string>('token', self.Token.token);
      Aj.TryGetValue<string>('scope', self.Token.scope);
      Aj.TryGetValue<string>('tenant', self.Token.tenant);
      Aj.TryGetValue<string>('redirectUri', self.Token.redirectUri);

      Aj.Free;
    finally
      // close File and free stream
      AF.Free;
    end;
    Result := self.Token.token <> '';
  end;
end;

procedure TMsTokenStorege.store();
var
  AF: TStringStream;
  Aj: TJSONObject;
begin
  if self.Token.token <> '' then
  begin
    Aj := TJSONObject.Create;
    Aj.AddPair('token', self.Token.token);
    Aj.AddPair('scope', self.Token.scope);
    Aj.AddPair('tenant', self.Token.tenant);
    Aj.AddPair('redirectUri', self.Token.redirectUri);


    // create stream and read token
    AF := TStringStream.Create(aj.ToJSON);
    Aj.Free;
    try
      if not DirectoryExists(IncludeTrailingPathDelimiter(GetHomePath)+self.AppName) then
        CreateDir(IncludeTrailingPathDelimiter(IncludeTrailingPathDelimiter(GetHomePath)+self.AppName));
      // save data to file
      AF.SaveToFile(self.BuildFilename());
    finally
      // free stream
      AF.Free;
    end;
  end;
end;

{ TRedirectUri }

class function TRedirectUri.Create(Port: word; URL: string): TRedirectUri;
begin
  Result := Default(TRedirectUri);
  Result.Port := Port;
  if (URL <> URL.Empty) and (not URL.StartsWith('/')) then URL := '/' + URL;
  Result.URL := URL;
end;

function TRedirectUri.GetRedirectUri: string;
begin
  Result := TNetEncoding.URL.Encode(self.Transport + self.Domain + ':' + IntToStr(self.Port) + self.URL);
end;

class function TMsClientInfo.Create(Tenant, ClientId: string;
  Scope: TArray<string>; RedirectUri: TRedirectUri; TokenStorage: TMsTokenStorege): TMsClientInfo;
begin
  Result := Default(TMsClientInfo);
  Result.Tenant := Tenant;
  Result.ClientId := ClientId;
  Result.Scope.scopes := Scope;
  Result.RedirectUri := RedirectUri;
  Result.TokenStorage := TokenStorage;
end;

function TMsClientInfo.CheckToken: boolean;
begin
  result := (
    (self.TokenStorage.Token.token <> '') and
    (self.TokenStorage.Token.scope = self.Scope.makeScopeString) and
    (self.TokenStorage.Token.tenant = self.Tenant) and
    (self.TokenStorage.Token.redirectUri = self.RedirectUri.GetRedirectUri)
  );
end;

class function TMsClientInfo.Create(Tenant, ClientId, ClientSecret: string;
  Scope: TArray<string>; RedirectUri: TRedirectUri): TMsClientInfo;
begin
Result := Default(TMsClientInfo);
  Result.Tenant := Tenant;
  Result.ClientId := ClientId;
  Result.ClientSecret := ClientSecret;
  Result.Scope.scopes := Scope;
  Result.RedirectUri := RedirectUri;
end;

{ TMsAdClientEvents }

class function TMsClientEvents.Create(OnPageOpen: TOnPageOpen;
  OnRequestError: TOnRequestError;
  WhileWaitingOnToken: TWhileWaitingOnToken): TMsClientEvents;
begin
  Result.OnPageOpen := OnPageOpen;
  result.OnRequestError := OnRequestError;
  Result.WhileWaitingOnToken := WhileWaitingOnToken;
end;

{ TMsAdDelegatedAuthenticator }

constructor TMsDelegatedAuthenticator.Create(ClientInfo: TMsClientInfo;
  ClientEvents: TMsClientEvents);
begin
  inherited Create;
  self.FAuthenticatorType := TAthenticatorType.ATDelegated;
  // setup HTTP Client
  self.FHttpClient := THTTPClient.Create;
  self.FHttpClient.Accept := 'application/json';
  self.FHttpClient.ContentType := 'application/x-www-form-urlencoded';
  self.FHttpClient.AcceptCharSet := TEncoding.UTF8.EncodingName;

  // set Variables
  self.FClientInfo := ClientInfo;
  self.FEvents := ClientEvents;
  self.FScope := ClientInfo.Scope;
end;

destructor TMsDelegatedAuthenticator.Destroy;
begin
  if self.FClientInfo.CheckToken then
  begin
    self.FClientInfo.TokenStorage.store;
  end;
  self.FHttpClient.Free;
  inherited;
end;

function TMsDelegatedAuthenticator.FDoRefreshToken: boolean;
var
  AUrl: string;
  ARequest: IHTTPRequest;
  AResponse: IHTTPResponse;
  ARequestData: TStringStream;

  AResponseJson: TJSONValue;
  AExpiresIn: int64;

  AError: TMsError;
begin
  // build Url
  AUrl := ''
  + 'https://login.microsoftonline.com/'
  + self.FClientInfo.Tenant + '/oauth2/v2.0/token';
  // create Request object
  ARequest := self.FHttpClient.GetRequest(sHTTPMethodPost, AUrl);
  // create Request Stream
  ARequestData := TStringStream.Create(''
  + 'client_id=' + self.FClientInfo.ClientId
  + '&scope=' + self.FScope.makeScopeString
  + '&refresh_token=' + self.FClientInfo.TokenStorage.Token.token
  + '&redirect_uri=' + self.FClientInfo.RedirectUri.GetRedirectUri
  + '&grant_type=refresh_token');
  ARequest.SourceStream := ARequestData;
  // Execute Request
  AResponse := self.FHttpClient.Execute(ARequest);
  // Free Request Data Stream
  ARequestData.Free;

  // try to parse the response data
  AResponseJson := TJSONValue.ParseJSONValue(AResponse.ContentAsString(TEncoding.UTF8));

  //Check Response and Extract Data
  if AResponse.StatusCode <> 200 then
  begin
    AError.HTTPerror_data := AResponse.ContentAsString(TEncoding.UTF8);
    AError.HTTPStatusCode := AResponse.StatusCode;
    AError.HTTPStatusText := AResponse.StatusText;
    Result := False;

    // containing an error message (maybe)
    if AResponseJson.TryGetValue<string>('error', AError.HTTPerror_name) then
    begin
      AError.HTTPerror_data := AResponse.ContentAsString(TEncoding.UTF8);

      AResponseJson.TryGetValue<string>('error_description', AError.HTTPerror_description);
      // check if the error is an "refresh Token Expired Message"
      if (AError.HTTPerror_description = 'invalid_grant') and ContainsText(AError.HTTPerror_description, 'AADSTS700082') then
      begin
        // Refresh token expired so do user auth
        Result := self.FDoUserAuth;
      end;
    end;

    if not Result then
      self.FEvents.OnRequestError(AError);

  end
  else
  begin
    // parse the response data containing the Token :)
    AResponseJson.TryGetValue<string>('access_token', self.FAccesToken);
    AResponseJson.TryGetValue<string>('refresh_token', self.FClientInfo.TokenStorage.Token.token);
    AResponseJson.TryGetValue<int64>('expires_in', AExpiresIn);
    // AResponseJson.TryGetValue<int64>('ext_expires_in', AExtExpiresIn);

    // calculate expiration time
    self.FAccesTokenExpiresAt := HttpToDate(AResponse.Date, True).ToUnix(True) + AExpiresIn;
    // Acces Token is Gathered so there we go:
    Result := True;
  end;
  // Free JsonResponse Object
  AResponseJson.Free;
end;

function TMsDelegatedAuthenticator.FDoUserAuth: boolean;
var
  AHttpServer: TIdHTTPServer;
  ACancel: boolean;
  AUrl: string;
  ARequest: IHttpRequest;
  ARequestData: TStringStream;
  AResponse: IHttpResponse;

  AResponseJson: TJSONValue;

  AExpiresIn: int64;

  AError: TMsError;
begin
  self.FAccesCodeSet := false;
  self.FAccesCodeErrorOccured := false;
  // run server and aquire AccesCode
  AHttpServer := TIdHTTPServer.Create();
  AHttpServer.Bindings.Add.SetBinding(self.FClientInfo.RedirectUri.IP, self.FClientInfo.RedirectUri.Port);
  AHttpServer.OnException := self.FOnIdException;
  AHttpServer.OnListenException := self.FOnIdListenException;
  AHttpServer.OnCommandError := self.FOnIdCommandError;
  AHttpServer.OnCommandGet := self.FOnCommandGet;
  AHttpServer.Active := True;

  // Create New State
  self.FState := Self.FCreateState;
  // open the Browser
  AUrl := ''
  + 'https://login.microsoftonline.com/'
  + self.FClientInfo.Tenant
  + '/oauth2/v2.0/authorize'
  + '?client_id=' + self.FClientInfo.ClientId
  + '&response_type=code'
  + '&redirect_uri=' + self.FClientInfo.RedirectUri.GetRedirectUri
  + '&response_mode=query'
  + '&scope=' + self.FScope.makeScopeString
  + '&state=' + self.FState;
  {$IFDEF MSWINDOWS}
  ShellExecute(0, 'open', PChar(AUrl), nil, nil, SW_SHOWNORMAL);
  {$ELSEIF POSIX}
  _system(PAnsiChar('open ' + AnsiString(AUrl)));
  {$ENDIF}

  // Wait for AccesCode to be aquired
  while (not self.FAccesCodeSet) and (not ACancel) and (not self.FAccesCodeErrorOccured) do self.FEvents.WhileWaitingOnToken(ACancel);

  // shutdown HttpServer
  AHttpServer.Active := false;
  AHttpServer.Free;

  if (not ACancel) and (not self.FAccesCodeErrorOccured) then
  begin
    // Get Acces Token With Acces Code
    // build Url
    AUrl := ''
    + 'https://login.microsoftonline.com/'
    + self.FClientInfo.Tenant + '/oauth2/v2.0/token';
    // create Request object
    ARequest := self.FHttpClient.GetRequest(sHTTPMethodPost, AUrl);
    // create Request Stream
    ARequestData := TStringStream.Create(''
    + 'client_id=' + self.FClientInfo.ClientId
    + '&scope=' + self.FScope.makeScopeString
    + '&code=' + self.FAccesCode
    + '&redirect_uri=' + self.FClientInfo.RedirectUri.GetRedirectUri
    + '&grant_type=authorization_code');
    ARequest.SourceStream := ARequestData;
    // Execute Request
    AResponse := self.FHttpClient.Execute(ARequest);
    // Free Request Data Stream
    ARequestData.Free;

    // try to parse the response data
    AResponseJson := TJSONValue.ParseJSONValue(AResponse.ContentAsString(TEncoding.UTF8));

    // Check Response And Extract Data
    if AResponse.StatusCode <> 200 then
    begin
      AError.HTTPerror_data := AResponse.ContentAsString(TEncoding.UTF8);
      AError.HTTPStatusCode := AResponse.StatusCode;
      AError.HTTPStatusText := AResponse.StatusText;
      Result := False;

      // containing an error message (maybe)
      if AResponseJson.TryGetValue<string>('error', AError.HTTPerror_name) then
      begin
        AError.HTTPerror_data := AResponse.ContentAsString(TEncoding.UTF8);

        AResponseJson.TryGetValue<string>('error_description', AError.HTTPerror_description);
      end;

      if not Result then
        self.FEvents.OnRequestError(AError);

    end
    else
    begin
      // parse the response data containing the Token :)
      AResponseJson.TryGetValue<string>('access_token', self.FAccesToken);
      AResponseJson.TryGetValue<string>('refresh_token', self.FClientInfo.TokenStorage.Token.token);
      AResponseJson.TryGetValue<int64>('expires_in', AExpiresIn);
      // AResponseJson.TryGetValue<int64>('ext_expires_in', AExtExpiresIn);

      // set correct values of token storage
      self.FClientInfo.TokenStorage.Token.scope := self.FScope.makeScopeString;
      self.FClientInfo.TokenStorage.Token.tenant := self.FClientInfo.Tenant;
      self.FClientInfo.TokenStorage.Token.redirectUri := self.FClientInfo.RedirectUri.GetRedirectUri;

      // calculate expiration time
      self.FAccesTokenExpiresAt := HttpToDate(AResponse.Date, True).ToUnix(True) + AExpiresIn;
      // Acces Token is Gathered so there we go:
      Result := True;
    end;
    AResponseJson.Free;
  end
  else
  begin
    Result := False;
  end;
end;

function TMsDelegatedAuthenticator.FForceRefresh: string;
begin
  if self.FClientInfo.TokenStorage.Token.token = '' then
    self.FClientInfo.TokenStorage.load;
  if Self.FDoRefreshToken then
    Result := self.FAccesToken
  else
    Result := '';
end;

function TMsDelegatedAuthenticator.FCreateState: string;
const
  StateDefaultLength = 200;
var
  AI: integer;
  AData: string;
begin
  // Create State
  for AI := 0 to StateDefaultLength do
  begin
    AData := AData + Char(Random(128));
  end;
  Result := TNetEncoding.Base64URL.Encode(AData);
end;

function TMsDelegatedAuthenticator.FGetRequestErrorEvent: TMsAuthenticator.TOnRequestError;
begin
  Result := self.FEvents.OnRequestError;
end;

function TMsDelegatedAuthenticator.FGetToken: string;
var
  ok: boolean;
begin
  if (self.FClientInfo.TokenStorage.Token.token = '') and not self.FClientInfo.CheckToken then
  begin
    // Refresh Token Is empty so it is tried to be loaded or a user auth must be done
    if self.FClientInfo.TokenStorage.load then
    begin
      if self.FClientInfo.CheckToken then
      begin
        // the Refresh Token was loaded
        ok := self.FDoRefreshToken;
      end
      else
      begin
        // The Refresh Token couldnt be loaded
        ok := self.FDoUserAuth;
      end;
    end
    else
    begin
      // The Refresh Token couldnt be loaded
      ok := self.FDoUserAuth;
    end;
  end
  else
  begin
    // the Refresh Token isnt Empty
    if self.FAccesToken = '' then
    begin
      // The Acces Token Is Empty so a refresh must be done
      ok := self.FDoRefreshToken;
    end
    else
    begin
      // the acces token isnt empty either
      if self.FAccesTokenExpiresAt <= TDateTime.NowUTC.ToUnix(True) then
      begin
        // The Acces Token Expired So a refresh must be done
        ok := self.FDoRefreshToken;
      end
      else
      begin
        // the acces token should be valid
        ok := true;
      end;
    end;
  end;

  if ok then
  begin
    // acces token should be ok so everything is fine
    Result := self.FAccesToken;
  end
  else
  begin
    // acces token isnt ok so a empty string is returned
    Result := '';
  end;
end;

procedure TMsDelegatedAuthenticator.FOnCommandGet(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
const
  Code = 'code';
  State = 'state';
  Error = 'error';
  Adminconstent = 'admin_consent';
  Error_unknown = 'unknown';
  ErrorDescription = 'error_description';
  Error_invalidRequest = 'invalid_request';
  Error_invalidRequestDescription = 'The "state" of the answer from Microsoft was not correct.';
var
  AError, AErrorDescription: string;
  AParams: TStringList;
begin
  // parse Url Params
  AParams := TStringList.Create;
  AParams.Delimiter := '&';
  AParams.StrictDelimiter := true;
  AParams.DelimitedText := ARequestInfo.QueryParams;
  // handle connection
  if (AParams.Values[Code] <> '') and (AParams.Values[State] <> '') then
  begin
    // Check if State is correct
    if AParams.Values[State] = Self.FState then
    begin
      // save Acces Code
      self.FAccesCode := AParams.Values[Code];
    end
    else
    begin
      // in case the state is not correct, "create" the error
      AError := Error_invalidRequest;
      AErrorDescription := Error_invalidRequestDescription;
    end;
  end
  else
  begin
    // try to get the error message, if there is none, just say unknown
    AError := AParams.Values[Error];
    if AError = '' then AError := Error_unknown;
    AErrorDescription := AParams.Values[ErrorDescription];
    if AErrorDescription = '' then
    begin
      AErrorDescription := AParams.Values['error_subcode'];
      if AErrorDescription = '' then
        AErrorDescription := Error_unknown;
    end;
  end;
  AParams.Free;

  // create the Response Page
  if (AError <> '') or (AErrorDescription <> '') then
  begin
    self.FAccesCodeErrorOccured := true;
    if (AError = 'access_denied') and (AErrorDescription = 'cancel') then
    begin
      self.FAccesCodeErrorIsCancel := true;
      AResponseInfo.ContentStream := TStringStream.Create(
      '<title>Login cancelled</title>The Authentication process was cancelled. You can close this tab now.'
      );
    end
    else
    begin
      self.FAccesCodeErrorIsCancel := false;
      // when there is an error, the error page is shown
      // TODO: Check if content stream is already a created object
      AResponseInfo.ContentStream := TStringStream.Create(
        '<title>Login error</title><b>Error:</b><br>' + AError +
        '<br><br><b>Description:</b><br>' + AErrorDescription
      );
    end;
  end
  else
  begin
    // if everything is ok, the OnPageOpen function is called and the Response
    // must be built there
    self.FEvents.OnPageOpen(AResponseInfo);
    // Set Variable
    self.FAccesCodeSet := true;
  end;
end;

procedure TMsDelegatedAuthenticator.FOnIdCommandError(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo;
  AException: Exception);
begin
end;

procedure TMsDelegatedAuthenticator.FOnIdException(AContext: TIdContext;
  AException: Exception);
begin
end;

procedure TMsDelegatedAuthenticator.FOnIdListenException(
  AThread: TIdListenerThread; AException: Exception);
begin
end;

{ TMsAdDeamonAuthenticator }

constructor TMsDeamonAuthenticator.Create(ClientInfo: TMsClientInfo;
  ClientEvents: TMsClientEvents);
begin
  inherited Create;
  self.FAuthenticatorType := TAthenticatorType.ATDeamon;
  // setup HTTP Client
  self.FHttpClient := THTTPClient.Create;
  self.FHttpClient.Accept := 'application/json';
  self.FHttpClient.ContentType := 'application/x-www-form-urlencoded';
  self.FHttpClient.AcceptCharSet := TEncoding.UTF8.EncodingName;

  // set Variables
  self.FClientInfo := ClientInfo;
  if self.FClientInfo.ClientSecret = '' then raise Exception.Create('Client secret cannot be empty for Deamon Authenticators');
  self.FEvents := ClientEvents;
  self.FScope := ClientInfo.Scope;
end;

destructor TMsDeamonAuthenticator.Destroy;
begin
  self.FHttpClient.Free;
  inherited;
end;

function TMsDeamonAuthenticator.FCreateState: string;
const
  StateDefaultLength = 200;
var
  AI: integer;
  AData: string;
begin
  // Create State
  for AI := 0 to StateDefaultLength do
  begin
    AData := AData + Char(Random(128));
  end;
  Result := TNetEncoding.Base64URL.Encode(AData);
end;

function TMsDeamonAuthenticator.FDoAdminAuth: boolean;
var
  AHttpServer: TIdHTTPServer;
  ACancel: boolean;
  AUrl: string;
begin
  self.FAdminConsentGiven := false;
  self.FAdminConsentErrorOccured := false;
  // run server and aquire AccesCode
  AHttpServer := TIdHTTPServer.Create();
  AHttpServer.Bindings.Add.SetBinding(self.FClientInfo.RedirectUri.IP, self.FClientInfo.RedirectUri.Port);
  AHttpServer.OnException := self.FOnIdException;
  AHttpServer.OnListenException := self.FOnIdListenException;
  AHttpServer.OnCommandError := self.FOnIdCommandError;
  AHttpServer.OnCommandGet := self.FOnCommandGet;
  AHttpServer.Active := True;

  // Create New State
  self.FState := Self.FCreateState;
  // open the Browser
  AUrl := ''
  + 'https://login.microsoftonline.com/'
  + self.FClientInfo.Tenant
  + '/oauth2/v2.0/authorize'
  + '?client_id=' + self.FClientInfo.ClientId
  + '&redirect_uri=' + self.FClientInfo.RedirectUri.GetRedirectUri
  + '&state=' + self.FState;
  {$IFDEF MSWINDOWS}
  ShellExecute(0, 'open', PChar(AUrl), nil, nil, SW_SHOWNORMAL);
  {$ELSEIF POSIX}
  _system(PAnsiChar('open ' + AnsiString(AUrl)));
  {$ENDIF}

  // Wait for AccesCode to be aquired
  while (not self.FAdminConsentGiven) and (not ACancel) and (not self.FAdminConsentErrorOccured) do self.FEvents.WhileWaitingOnToken(ACancel);

  // shutdown HttpServer
  AHttpServer.Active := false;
  AHttpServer.Free;

  Result := false;
  if not ACancel and (self.FAdminConsentErrorOccured) then
  begin
    Result := Self.FDoGetNewToken;
  end
end;

function TMsDeamonAuthenticator.FDoGetNewToken: boolean;
var
  AUrl: string;
  ARequest: IHTTPRequest;
  AResponse: IHTTPResponse;
  ARequestData: TStringStream;

  AResponseJson: TJSONValue;
  AExpiresIn: int64;
  AError: TMsError;
begin
  // build Url
  AUrl := ''
  + 'https://login.microsoftonline.com/'
  + self.FClientInfo.Tenant + '/oauth2/v2.0/token';
  // create Request object
  ARequest := self.FHttpClient.GetRequest(sHTTPMethodPost, AUrl);
  // create Request Stream
  ARequestData := TStringStream.Create(''
  + 'client_id=' + self.FClientInfo.ClientId
  + '&scope=' + self.FScope.makeScopeString
  + '&client_secret=' + self.FClientInfo.ClientSecret
  + '&grant_type=client_credentials');
  ARequest.SourceStream := ARequestData;
  // Execute Request
  AResponse := self.FHttpClient.Execute(ARequest);
  // Free Request Data Stream
  ARequestData.Free;

  // try to parse the response data
  AResponseJson := TJSONValue.ParseJSONValue(AResponse.ContentAsString(TEncoding.UTF8));

  //Check Response and Extract Data
  if AResponse.StatusCode <> 200 then
  begin
    AError.HTTPerror_data := AResponse.ContentAsString(TEncoding.UTF8);
    AError.HTTPStatusCode := AResponse.StatusCode;
    AError.HTTPStatusText := AResponse.StatusText;
    Result := False;

    // containing an error message (maybe)
    if AResponseJson.TryGetValue<string>('error', AError.HTTPerror_name) then
    begin

      AResponseJson.TryGetValue<string>('error_description', AError.HTTPerror_description);

      // check if the error is an "refresh Token Expired Message"
      if (AError.HTTPerror_name = 'invalid_grant') and ContainsText(AError.HTTPerror_description, 'AADSTS700082') then
      begin
        // Refresh token expired so do user auth
        Result := self.FDoAdminAuth;
      end
    end;

    if not Result then
      self.FEvents.OnRequestError(AError);
  end
  else
  begin
    // parse the response data containing the Token :)
    AResponseJson.TryGetValue<string>('access_token', self.FAccesToken);
    AResponseJson.TryGetValue<int64>('expires_in', AExpiresIn);
    // AResponseJson.TryGetValue<int64>('ext_expires_in', AExtExpiresIn);

    // calculate expiration time
    self.FAccesTokenExpiresAt := HttpToDate(AResponse.Date, True).ToUnix(True) + AExpiresIn;
    // Acces Token is Gathered so there we go:
    Result := True;
  end;
  // Free JsonResponse Object
  AResponseJson.Free;
end;

function TMsDeamonAuthenticator.FForceRefresh: string;
begin
  if self.FDoGetNewToken then
    Result := self.FAccesToken
  else
    Result := '';
end;

function TMsDeamonAuthenticator.FGetRequestErrorEvent: TMsAuthenticator.TOnRequestError;
begin
  Result := self.FEvents.OnRequestError;
end;

function TMsDeamonAuthenticator.FGetToken: string;
var
  ok: boolean;
begin
  if self.FAccesToken = '' then
  begin
    ok := self.FDoGetNewToken;
  end
  else
  begin
    if self.FAccesTokenExpiresAt <= TDateTime.NowUTC.ToUnix(True) then
    begin
      ok := self.FDoGetNewToken;
    end
    else
    begin
      ok := True;
    end;
  end;

  if ok then
    Result := self.FAccesToken
  else
    Result := '';
end;

procedure TMsDeamonAuthenticator.FOnCommandGet(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo);
const
  Code = 'code';
  State = 'state';
  Error = 'error';
  Adminconstent = 'admin_consent';
  Error_unknown = 'unknown';
  ErrorDescription = 'error_description';
  Error_invalidRequest = 'invalid_request';
  Error_invalidRequestDescription = 'The "state" of the answer from Microsoft was not correct.';
var
  AError, AErrorDescription: string;
  AParams: TStringList;
begin
  // parse Url Params
  AParams := TStringList.Create;
  AParams.Delimiter := '&';
  AParams.StrictDelimiter := true;
  AParams.DelimitedText := ARequestInfo.QueryParams;
  // handle connection
  if (AParams.Values[Adminconstent] <> '') and (AParams.Values[State] <> '') then
  begin
    // Check if State is correct
    if AParams.Values[State] = Self.FState then
    begin
      // everything is ok :)

    end
    else
    begin
      // in case the state is not correct, "create" the error
      AError := Error_invalidRequest;
      AErrorDescription := Error_invalidRequestDescription;
    end;
  end
  else
  begin
    // try to get the error message, if there is none, just say unknown
    AError := AParams.Values[Error];
    if AError = '' then AError := Error_unknown;
    AErrorDescription := AParams.Values[ErrorDescription];
    if AErrorDescription = '' then AErrorDescription := Error_unknown;
  end;
  AParams.Free;

  // create the Response Page
  if (AError <> '') or (AErrorDescription <> '') then
  begin
    self.FAdminConsentErrorOccured := true;
    // when there is an error, the error page is shown
    // TODO: Check if content stream is already a created object
    AResponseInfo.ContentStream := TStringStream.Create(
      '<b>Error:</b><br>' + AError +
      '<br><br><b>Description:</b><br>' + AErrorDescription
    );
  end
  else
  begin
    // if everything is ok, the OnPageOpen function is called and the Response
    // must be built there
    self.FEvents.OnPageOpen(AResponseInfo);
    // Set Variable
    self.FAdminConsentGiven := true;
  end;
end;

procedure TMsDeamonAuthenticator.FOnIdCommandError(AContext: TIdContext;
  ARequestInfo: TIdHTTPRequestInfo; AResponseInfo: TIdHTTPResponseInfo;
  AException: Exception);
begin

end;

procedure TMsDeamonAuthenticator.FOnIdException(AContext: TIdContext;
  AException: Exception);
begin

end;

procedure TMsDeamonAuthenticator.FOnIdListenException(
  AThread: TIdListenerThread; AException: Exception);
begin

end;

{ TMsAdAdapter }

constructor TMsAdapter.Create(Authenticator: TMsAuthenticator);
begin
  self.FAuthenticator := Authenticator;
end;

function TMsAdapter.FForeRefresh: string;
begin
  Result := self.FAuthenticator.FForceRefresh;
end;

function TMsAdapter.FGetAuthenticatorType: TAthenticatorType;
begin
  Result := self.FAuthenticator.FAuthenticatorType;
end;

function TMsAdapter.FGetHttpClient: THttpClient;
begin
  Result := self.FAuthenticator.FHttpClient;
end;

function TMsAdapter.FGetRequestErrorEvent: TOnRequestError;
begin
  Result := self.FAuthenticator.FGetRequestErrorEvent();
end;

function TMsAdapter.FGetToken: string;
var
  AToken: string;
begin
  Result := '';
  AToken := self.FAuthenticator.FGetToken;
  if AToken <> '' then
    Result := 'Bearer ' + AToken;
end;

{ TMsAdAuthenticator }

class function TMsAuthenticator.Create(AuthenticatorType: TAthenticatorType;
  ClientInfo: TMsClientInfo;
  ClientEvents: TMsClientEvents): TMsAuthenticator;
begin
  Result := nil;
  case AuthenticatorType of
    ATDelegated: Result := TMsDelegatedAuthenticator.Create(ClientInfo, ClientEvents);
    ATDeamon: Result := TMsDeamonAuthenticator.Create(ClientInfo, ClientEvents);
  end;
end;

{ TMsAdClientInfo.TScope }

function TMsClientInfo.TScope.makeScopeString: string;
var
  AI: integer;
  AEncoded: TArray<string>;
begin
  // URL-Encode scopes
  SetLength(AEncoded, Length(self.scopes));
  for AI := 0 to Length(self.scopes)-1 do AEncoded[AI] := TNetEncoding.URL.Encode(self.scopes[AI]);
  // check if offline Acces Scope is missing and add it if applicable
  if IndexText('offline_access', AEncoded) = -1 then AEncoded := AEncoded + ['offline_access'];
  // join them with ' '
  Result := String.Join(' ', AEncoded);
end;

{ TMsError }

class operator TMsError.Initialize(out Dest: TMsError);
begin
  Dest.HTTPStatusCode := 0;
  Dest.HTTPStatusText := '';
  Dest.HTTPurl := '';
  Dest.HTTPMethod := '';
  Dest.HTTPreq_Header := [];
  Dest.HTTPres_header := [];
  Dest.HTTPerror_data := '';
  Dest.HTTPerror_name := '';
  Dest.HTTPerror_description := '';
  Dest.INTERNALerror_name := '';
  Dest.INTERNALerror_message := '';
end;

// seeding so random ist really random
var
  Seeded: boolean;
begin
  if not Seeded then
  begin
    RandSeed := integer(Now.ToUnix()-MainThreadID+integer(@Seeded));
    Seeded := true;
  end;
end.
