












void func_0(void)

{
  uint uVar1;
  size_t sVar2;
  char *pcVar3;
  FILE *pFVar4;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  sVar2 = _strlen(local_7c);
  pcVar3 = _getenv("ADD");
  if (pcVar3 != (char *)0x0) {
    ___strncat_chk(local_7c + sVar2,pcVar3,99 - sVar2,0xffffffffffffffff);
  }
  pFVar4 = _popen(local_7c,"w");
  if (pFVar4 != (FILE *)0x0) {
    uVar1 = _pclose(pFVar4);
    pFVar4 = (FILE *)(ulong)uVar1;
  }
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail(pFVar4);
  }
  return;
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




