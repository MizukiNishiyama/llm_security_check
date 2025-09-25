










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
  int iVar1;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004010;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  if (_GLOBAL_CONST_FIVE == 5) {
    ___strcat_chk(local_7c,"*.*",0xffffffffffffffff);
  }
  else {
    func_4("Benign, fixed string");
  }
  iVar1 = _system(local_7c);
  if (iVar1 != 0) {
    func_4("command execution failed!");
                    
    _exit(1);
  }
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail();
  }
  return;
}







void func_3(void)

{
  int iVar1;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004010;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  if (_GLOBAL_CONST_FIVE == 5) {
    ___strcat_chk(local_7c,"*.*",0xffffffffffffffff);
  }
  iVar1 = _system(local_7c);
  if (iVar1 != 0) {
    func_4("command execution failed!");
                    
    _exit(1);
  }
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail();
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