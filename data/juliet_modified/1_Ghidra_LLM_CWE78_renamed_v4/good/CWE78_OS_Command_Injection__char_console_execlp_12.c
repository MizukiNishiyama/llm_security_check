










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
  undefined1 local_7c;
  undefined1 local_7b;
  undefined1 local_7a;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004010;
  _memset(&local_7c,0,100);
  local_7c = 0x6c;
  local_7b = 0x73;
  local_7a = 0x20;
  iVar1 = func_4();
  if (iVar1 == 0) {
    ___strcat_chk(&local_7c,"*.*",0xffffffffffffffff);
  } else {
    ___strcat_chk(&local_7c,"*.*",0xffffffffffffffff);
  }
  iVar1 = _execlp("sh","sh");
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail(iVar1);
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




