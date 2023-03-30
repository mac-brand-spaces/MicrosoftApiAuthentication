unit key_press_helper;

interface

uses
    Windows, Messages, SysUtils, Classes;

function KeyPressed(ExpectedKey: Word):Boolean;

implementation

function KeyPressed(ExpectedKey: Word):Boolean;
  var lpNumberOfEvents: DWORD;
      lpBuffer: TInputRecord;
      lpNumberOfEventsRead : DWORD;
      nStdHandle: THandle;
  begin
    result := false;
    nStdHandle := GetStdHandle(STD_INPUT_HANDLE);
    lpNumberOfEvents := 0;
    GetNumberOfConsoleInputEvents(nStdHandle,lpNumberOfEvents);
    if lpNumberOfEvents<>0 then begin
      PeekConsoleInput(nStdHandle,lpBuffer,1,lpNumberOfEventsRead);
      if lpNumberOfEventsRead<>0 then
        if lpBuffer.EventType=KEY_EVENT then
          if lpBuffer.Event.KeyEvent.bKeyDown and
             ((ExpectedKey=0) or (lpBuffer.Event.KeyEvent.wVirtualKeyCode=ExpectedKey)) then
            result := true else
            FlushConsoleInputBuffer(nStdHandle) else
          FlushConsoleInputBuffer(nStdHandle);
    end;
  end;

end.