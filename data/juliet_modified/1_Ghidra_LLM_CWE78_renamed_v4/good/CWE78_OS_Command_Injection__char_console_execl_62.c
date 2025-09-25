












void CWE78_OS_Command_Injection__char_console_execl_62::func_0(void)

{
  func_1();
  return;
}







void func_1(void)

{
  int iVar1;
  char *local_88;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  local_88 = local_7c;
  CWE78_OS_Command_Injection__char_console_execl_62::func_3(&local_88);
  iVar1 = _execl("/bin/sh","/bin/sh");
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail(iVar1);
  }
  return;
}







undefined4 func_2(void)

{
  time_t tVar1;
  
  tVar1 = _time((time_t *)0x0);
  _srand((uint)tVar1);
  func_4("Calling ...");
  CWE78_OS_Command_Injection__char_console_execl_62::func_0();
  func_4("Finished ");
  return 0;
}









void CWE78_OS_Command_Injection__char_console_execl_62::func_3(char **param_1)

{
  _strcat(*param_1,"*.*");
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