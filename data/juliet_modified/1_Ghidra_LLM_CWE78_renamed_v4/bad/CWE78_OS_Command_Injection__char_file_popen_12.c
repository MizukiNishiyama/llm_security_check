










void func_0(void)

{
  int iVar1;
  uint uVar2;
  size_t sVar3;
  FILE *pFVar4;
  char *pcVar5;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  iVar1 = func_3();
  if (iVar1 == 0) {
    ___strcat_chk(local_7c,"*.*",0xffffffffffffffff);
  }
  else {
    sVar3 = _strlen(local_7c);
    if ((1 < 100 - sVar3) && (pFVar4 = _fopen("/tmp/file.txt","r"), pFVar4 != (FILE *)0x0)) {
      pcVar5 = _fgets(local_7c + sVar3,100 - (int)sVar3,pFVar4);
      if (pcVar5 == (char *)0x0) {
        func_2("fgets() failed");
        local_7c[sVar3] = '\0';
      }
      _fclose(pFVar4);
    }
  }
  pFVar4 = _popen(local_7c,"w");
  if (pFVar4 != (FILE *)0x0) {
    uVar2 = _pclose(pFVar4);
    pFVar4 = (FILE *)(ulong)uVar2;
  }
  if (*(long *)PTR____stack_chk_guard_100004000 == local_18) {
    return;
  }
                    
  ___stack_chk_fail(pFVar4);
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







int func_3(void)

{
  int iVar1;
  
  iVar1 = _rand();
  return iVar1 % 2;
}




