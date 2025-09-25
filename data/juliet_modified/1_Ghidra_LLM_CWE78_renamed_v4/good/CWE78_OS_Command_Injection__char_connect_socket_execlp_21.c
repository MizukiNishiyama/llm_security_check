










void func_0(void)

{
  func_2();
  func_4();
  return;
}







undefined4 func_1(void)

{
  time_t tVar1;
  
  tVar1 = _time((time_t *)0x0);
  _srand((uint)tVar1);
  func_6("Calling ...");
  func_0();
  func_6("Finished ");
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
  DAT_100008000 = 0;
  func_3(&local_7c);
  iVar1 = _execlp("sh","sh");
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail(iVar1);
  }
  return;
}







undefined8 func_3(undefined8 param_1)

{
  if (DAT_100008000 == 0) {
    ___strcat_chk(param_1,"*.*",0xffffffffffffffff);
  }
  else {
    func_6("Benign, fixed string");
  }
  return param_1;
}







void func_4(void)

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
  DAT_100008004 = 1;
  func_5(&local_7c);
  iVar1 = _execlp("sh","sh");
  if (*(long *)PTR____stack_chk_guard_100004010 != local_18) {
                    
    ___stack_chk_fail(iVar1);
  }
  return;
}







undefined8 func_5(undefined8 param_1)

{
  if (DAT_100008004 != 0) {
    ___strcat_chk(param_1,"*.*",0xffffffffffffffff);
  }
  return param_1;
}







ulong func_6(ulong param_1)

{
  uint uVar1;
  
  if (param_1 != 0) {
    uVar1 = _printf("%s\n");
    param_1 = (ulong)uVar1;
  }
  return param_1;
}