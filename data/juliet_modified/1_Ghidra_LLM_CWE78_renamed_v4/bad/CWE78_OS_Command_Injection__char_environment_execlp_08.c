










void func_0(void)

{
  int iVar1;
  size_t sVar2;
  char *pcVar3;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  iVar1 = func_2();
  if (iVar1 != 0) {
    sVar2 = _strlen(local_7c);
    pcVar3 = _getenv("ADD");
    if (pcVar3 != (char *)0x0) {
      ___strncat_chk(local_7c + sVar2,pcVar3,99 - sVar2,0xffffffffffffffff);
    }
  }
  iVar1 = _execlp("sh","sh");
  if (*(long *)PTR____stack_chk_guard_100004000 == local_18) {
    return;
  }
                    
  ___stack_chk_fail(iVar1);
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







undefined8 func_2(void)

{
  return 1;
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




