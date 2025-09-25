void func_0(void)

{
  int iVar1;
  char *pcVar2;
  undefined1 local_7c;
  undefined1 local_7b;
  undefined1 local_7a;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(&local_7c,0,100);
  local_7c = 0x6c;
  local_7b = 0x73;
  local_7a = 0x20;
  _CWE78_OS_Command_Injection__char_environment_system_22_badGlobal = 1;
  pcVar2 = (char *)func_2(&local_7c);
  iVar1 = _system(pcVar2);
  if (iVar1 != 0) {
    func_3("command execution failed!");
                    
    _exit(1);
  }
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail();
  }
  return;
}