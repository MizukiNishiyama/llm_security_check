










void func_0(void)

{
  char *pcVar1;
  int iVar2;
  size_t sVar3;
  char *pcVar4;
  char acStack_7d [101];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  pcVar1 = acStack_7d + 1;
  _memset(pcVar1,0,100);
  acStack_7d[1] = 0x6c;
  acStack_7d[2] = 0x73;
  acStack_7d[3] = 0x20;
  sVar3 = _strlen(pcVar1);
  if (1 < 100 - sVar3) {
    pcVar4 = _fgets(pcVar1 + sVar3,100 - (int)sVar3,*(FILE **)PTR____stdinp_100004018);
    if (pcVar4 == (char *)0x0) {
      func_2("fgets() failed");
      pcVar1[sVar3] = '\0';
    }
    else {
      sVar3 = _strlen(pcVar1);
      if ((sVar3 != 0) && (pcVar1[sVar3 - 1] == '\n')) {
        pcVar1[sVar3 - 1] = '\0';
      }
    }
  }
  iVar2 = _execl("/bin/sh","/bin/sh");
  if (*(long *)PTR____stack_chk_guard_100004000 == local_18) {
    return;
  }
                    
  ___stack_chk_fail(iVar2);
}







undefined4 func_1(void)

{
  time_t tVar1;
  
  tVar1 = _time((time_t *)0x0);
  _srand((uint)tVar1);
  func_2("Calling ...");
  func_0();
  func_2("Finished ");
  return 0;
}







ulong func_2(ulong param_1)

{
  uint uVar1;
  
  if (param_1 != 0) {
    uVar1 = _printf("%s\n");
    param_1 = (ulong)uVar1;
  }
  return param_1;
}