












FILE * __thiscall
CWE78_OS_Command_Injection__char_console_popen_81::
CWE78_OS_Command_Injection__char_console_popen_81_goodG2B::action
          (CWE78_OS_Command_Injection__char_console_popen_81_goodG2B *this,char *param_1)

{
  uint uVar1;
  FILE *pFVar2;
  
  pFVar2 = _popen(param_1,"w");
  if (pFVar2 != (FILE *)0x0) {
    uVar1 = _pclose(pFVar2);
    pFVar2 = (FILE *)(ulong)uVar1;
  }
  return pFVar2;
}