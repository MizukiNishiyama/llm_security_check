









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
  iVar1 = _system(local_7c);
  if (iVar1 != 0) {
    func_3("command execution failed!");
                    
    _exit(1);
  }
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail();
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




