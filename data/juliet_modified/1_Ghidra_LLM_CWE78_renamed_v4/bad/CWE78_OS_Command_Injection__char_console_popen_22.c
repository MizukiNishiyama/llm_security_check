










void func_0(void)

{
  uint uVar1;
  char *pcVar2;
  FILE *pFVar3;
  undefined1 local_7c;
  undefined1 local_7b;
  undefined1 local_7a;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(&local_7c,0,100);
  local_7c = 0x6c;
  local_7b = 0x73;
  local_7a = 0x20;
  _CWE78_OS_Command_Injection__char_console_popen_22_badGlobal = 1;
  pcVar2 = (char *)func_2(&local_7c);
  pFVar3 = _popen(pcVar2,"w");
  if (pFVar3 != (FILE *)0x0) {
    uVar1 = _pclose(pFVar3);
    pFVar3 = (FILE *)(ulong)uVar1;
  }
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail(pFVar3);
  }
  return;
}