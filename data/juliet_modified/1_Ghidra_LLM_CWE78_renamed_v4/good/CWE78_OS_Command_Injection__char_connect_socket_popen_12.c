










void func_0(void)

{
  func_2();
  return;
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







void func_2(void)

{
  int iVar1;
  uint uVar2;
  FILE *pFVar3;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004010;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  iVar1 = func_4();
  if (iVar1 == 0) {
    ___strcat_chk(local_7c,"*.*",0xffffffffffffffff);
  } else {
    ___strcat_chk(local_7c,"*.*",0xffffffffffffffff);
  }
  pFVar3 = _popen(local_7c,"w");
  if (pFVar3 != (FILE *)0x0) {
    uVar2 = _pclose(pFVar3);
    pFVar3 = (FILE *)(ulong)uVar2;
  }
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail(pFVar3);
  }
  return;
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







int func_4(void)

{
  int iVar1;
  
  iVar1 = _rand();
  return iVar1 % 2;
}




