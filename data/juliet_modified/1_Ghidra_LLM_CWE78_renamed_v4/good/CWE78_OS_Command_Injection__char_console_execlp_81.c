












int CWE78_OS_Command_Injection__char_console_execlp_81::
    CWE78_OS_Command_Injection__char_console_execlp_81_goodG2B::func_0(char *param_1)

{
  int iVar1;
  
  iVar1 = _execlp("sh","sh");
  return iVar1;
}