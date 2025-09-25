










void func_0(void)

{
  func_2();
  func_3();
  return;
}







undefined4 func_1(void)

{
  time_t tVar1;
  
  tVar1 = _time((time_t *)0x0);
  _srand((uint)tVar1);
  func_6("Calling ...");
  func_0();
  func_6("Finished ");
  return 0;
}







void func_2(void)

{
  uint uVar1;
  char *pcVar2;
  FILE *pFVar3;
  undefined1 local_7c;
  undefined1 local_7b;
  undefined1 local_7a;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004010;
  _memset(&local_7c,0,100);
  local_7c = 0x6c;
  local_7b = 0x73;
  local_7a = 0x20;
  _CWE78_OS_Command_Injection__char_console_popen_22_goodG2B1Global = 0;
  pcVar2 = (char *)func_4(&local_7c);
  pFVar3 = _popen(pcVar2,"w");
  if (pFVar3 != (FILE *)0x0) {
    uVar1 = _pclose(pFVar3);
    pFVar3 = (FILE *)(ulong)uVar1;
  }
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail(pFVar3);
  }
  return;
}







void func_3(void)

{
  uint uVar1;
  char *pcVar2;
  FILE *pFVar3;
  undefined1 local_7c;
  undefined1 local_7b;
  undefined1 local_7a;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004010;
  _memset(&local_7c,0,100);
  local_7c = 0x6c;
  local_7b = 0x73;
  local_7a = 0x20;
  _CWE78_OS_Command_Injection__char_console_popen_22_goodG2B2Global = 1;
  pcVar2 = (char *)func_5(&local_7c);
  pFVar3 = _popen(pcVar2,"w");
  if (pFVar3 != (FILE *)0x0) {
    uVar1 = _pclose(pFVar3);
    pFVar3 = (FILE *)(ulong)uVar1;
  }
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail(pFVar3);
  }
  return;
}







undefined8 func_4(undefined8 param_1)

{
  if (_CWE78_OS_Command_Injection__char_console_popen_22_goodG2B1Global == 0) {
    ___strcat_chk(param_1,"*.*",0xffffffffffffffff);
  }
  else {
    func_6("Benign, fixed string");
  }
  return param_1;
}







undefined8 func_5(undefined8 param_1)

{
  if (_CWE78_OS_Command_Injection__char_console_popen_22_goodG2B2Global != 0) {
    ___strcat_chk(param_1,"*.*",0xffffffffffffffff);
  }
  return param_1;
}







ulong func_6(ulong param_1)

{
  uint uVar1;
  
  if (param_1 != 0) {
    uVar1 = _printf("%s\n");
    param_1 = (ulong)uVar1;
  }
  return param_1;
}