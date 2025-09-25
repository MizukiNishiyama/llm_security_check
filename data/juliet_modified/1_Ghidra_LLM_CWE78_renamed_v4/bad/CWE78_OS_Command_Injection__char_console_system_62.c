












void CWE78_OS_Command_Injection__char_console_system_62::func_0(void)

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
  func_2(&local_88);
  iVar1 = _system(local_88);
  if (iVar1 != 0) {
    func_3("command execution failed!");
                    
    _exit(1);
  }
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail();
  }
  return;
}