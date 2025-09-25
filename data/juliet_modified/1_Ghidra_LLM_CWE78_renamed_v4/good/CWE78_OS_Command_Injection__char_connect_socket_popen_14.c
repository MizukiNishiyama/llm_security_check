










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
  func_4("Calling ...");
  func_0();
  func_4("Finished ");
  return 0;
}







void func_2(void)

{
  uint uVar1;
  FILE *pFVar2;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004010;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  if (_globalFive == 5) {
    ___strcat_chk(local_7c,"*.*",0xffffffffffffffff);
  }
  else {
    func_4("Benign, fixed string");
  }
  pFVar2 = _popen(local_7c,"w");
  if (pFVar2 != (FILE *)0x0) {
    uVar1 = _pclose(pFVar2);
    pFVar2 = (FILE *)(ulong)uVar1;
  }
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail(pFVar2);
  }
  return;
}







void func_3(void)

{
  uint uVar1;
  FILE *pFVar2;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004010;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  if (_globalFive == 5) {
    ___strcat_chk(local_7c,"*.*",0xffffffffffffffff);
  }
  pFVar2 = _popen(local_7c,"w");
  if (pFVar2 != (FILE *)0x0) {
    uVar1 = _pclose(pFVar2);
    pFVar2 = (FILE *)(ulong)uVar1;
  }
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail(pFVar2);
  }
  return;
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