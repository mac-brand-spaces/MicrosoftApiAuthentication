unit testModule;

interface

uses
  MicrosoftApiAuthenticator,
  System.Net.URLClient;

type
  TtestModule = class(TMsAdapter)
  private
    function GetAccessToken: string;
  public
    property AccessToken: string read GetAccessToken;
    procedure raiseError;
  end;

implementation

{ TtestModule }

function TtestModule.GetAccessToken: string;
begin
  Result := self.Token;
end;

procedure TtestModule.raiseError;
var
  AError: TMsError;
begin
  AError.HTTPStatusCode := 400;
  AError.HTTPStatusText := 'Bad Request';
  AError.HTTPurl := 'http://www.google.com';
  AError.HTTPMethod := 'GET';
  AError.HTTPreq_Header := [TNetHeader.Create('Accept', 'application/json')];
  AError.HTTPres_header := [TNetHeader.Create('Content-Type', 'application/json')];
  AError.HTTPerror_data := '{"error":"invalid_request","error_description":"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."}';
  AError.HTTPerror_name := 'invalid_request';
  AError.HTTPerror_description := 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.';
  AError.INTERNALerror_name := 'invalid_request';
  AError.INTERNALerror_message := 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.';
  self.OnRequestError(AError);
end;

end.