










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
  func_4("Calling ...");
  func_0();
  func_4("Finished ");
  return 0;
}







void func_2(void)

{
  undefined1 local_a4;
  undefined1 local_a3;
  undefined1 local_a2;
  undefined1 auStack_40 [16];
  undefined1 *local_30;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004010;
  _memset(&local_a4,0,100);
  local_a4 = 0x6c;
  local_a3 = 0x73;
  local_a2 = 0x20;
  ___strcat_chk(&local_a4,"*.*",0xffffffffffffffff);
  local_30 = &local_a4;
  func_3(auStack_40);
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail();
  }
  return;
}







FILE * func_3(long param_1)

{
  uint uVar1;
  FILE *pFVar2;
  
  pFVar2 = _popen(*(char **)(param_1 + 0x10),"w");
  if (pFVar2 != (FILE *)0x0) {
    uVar1 = _pclose(pFVar2);
    pFVar2 = (FILE *)(ulong)uVar1;
  }
  return pFVar2;
}







ulong func_4(ulong param_1)

{
  uint uVar1;
  
  if (param_1 != 0) {
    uVar1 = _printf("%s\n");
    param_1 = (ulong)uVar1;
  }
  return param_1;
}




