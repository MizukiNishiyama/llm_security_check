










void func_0(void)

{
  size_t sVar1;
  char *pcVar2;
  char *local_88;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  local_88 = local_7c;
  sVar1 = _strlen(local_7c);
  if (1 < 100 - sVar1) {
    pcVar2 = _fgets(local_88 + sVar1,100 - (int)sVar1,*(FILE **)PTR____stdinp_100004018);
    if (pcVar2 == (char *)0x0) {
      func_3("fgets() failed");
      local_88[sVar1] = '\0';
    }
    else {
      sVar1 = _strlen(local_88);
      if ((sVar1 != 0) && (local_88[sVar1 - 1] == '\n')) {
        local_88[sVar1 - 1] = '\0';
      }
    }
  }
  func_2(&local_88);
  if (*(long *)PTR____stack_chk_guard_100004000 == local_18) {
    return;
  }
                    
  ___stack_chk_fail();
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







int func_2(void)

{
  int iVar1;
  
  iVar1 = _execlp("sh","sh");
  return iVar1;
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