










void func_0(void)

{
  char *pcVar1;
  int iVar2;
  uint uVar3;
  size_t sVar4;
  char *pcVar5;
  FILE *pFVar6;
  char acStack_7d [101];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  pcVar1 = acStack_7d + 1;
  _memset(pcVar1,0,100);
  acStack_7d[1] = 0x6c;
  acStack_7d[2] = 0x73;
  acStack_7d[3] = 0x20;
  iVar2 = func_2();
  if ((iVar2 != 0) && (sVar4 = _strlen(pcVar1), 1 < 100 - sVar4)) {
    pcVar5 = _fgets(pcVar1 + sVar4,100 - (int)sVar4,*(FILE **)PTR____stdinp_100004018);
    if (pcVar5 == (char *)0x0) {
      func_3("fgets() failed");
      pcVar1[sVar4] = '\0';
    }
    else {
      sVar4 = _strlen(pcVar1);
      if ((sVar4 != 0) && (pcVar1[sVar4 - 1] == '\n')) {
        pcVar1[sVar4 - 1] = '\0';
      }
    }
  }
  pFVar6 = _popen(pcVar1,"w");
  if (pFVar6 != (FILE *)0x0) {
    uVar3 = _pclose(pFVar6);
    pFVar6 = (FILE *)(ulong)uVar3;
  }
  if (*(long *)PTR____stack_chk_guard_100004000 == local_18) {
    return;
  }
                    
  ___stack_chk_fail(pFVar6);
}







undefined4 func_1(void)

{
  time_t tVar1;
  
  tVar1 = _time((time_t *)0x0);
  _srand((uint)tVar1);
  func_3("Calling ...");
  func_0();
  func_3("Finished ");
  return 0;
}







undefined8 func_2(void)

{
  return 1;
}







ulong func_3(ulong param_1)

{
  uint uVar1;
  
  if (param_1 != 0) {
    uVar1 = _printf("%s\n");
    param_1 = (ulong)uVar1;
  }
  return param_1;
}




