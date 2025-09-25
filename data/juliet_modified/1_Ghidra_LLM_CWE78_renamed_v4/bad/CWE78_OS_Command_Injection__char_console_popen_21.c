










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
  DAT_100008000 = 1;
  pcVar2 = (char *)func_1(&local_7c);
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







char * func_1(char *param_1)

{
  size_t sVar1;
  char *pcVar2;
  
  if ((DAT_100008000 != 0) && (sVar1 = _strlen(param_1), 1 < 100 - sVar1)) {
    pcVar2 = _fgets(param_1 + sVar1,100 - (int)sVar1,*(FILE **)PTR____stdinp_100004030);
    if (pcVar2 == (char *)0x0) {
      func_3("fgets() failed");
      param_1[sVar1] = '\0';
    }
    else {
      sVar1 = _strlen(param_1);
      if ((sVar1 != 0) && (param_1[sVar1 - 1] == '\n')) {
        param_1[sVar1 - 1] = '\0';
      }
    }
  }
  return param_1;
}







undefined4 func_2(void)

{
  time_t tVar1;
  
  tVar1 = _time((time_t *)0x0);
  _srand((uint)tVar1);
  func_3("Calling ...");
  func_0();
  func_3("Finished ");
  return 0;
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




